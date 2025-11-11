#!/bin/bash
set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
CONFIG_DIR="/etc/gost"
META_FILE="$CONFIG_DIR/metadata.json"

print_info() {
    if [ -t 1 ]; then
        echo -e "\033[0;34m[INFO]\033[0m $1"
    else
        echo "[INFO] $1"
    fi
}

print_success() {
    if [ -t 1 ]; then
        echo -e "\033[0;32m[SUCCESS]\033[0m $1"
    else
        echo "[SUCCESS] $1"
    fi
}

print_warning() {
    if [ -t 1 ]; then
        echo -e "\033[1;33m[WARNING]\033[0m $1"
    else
        echo "[WARNING] $1"
    fi
}

print_error() {
    if [ -t 1 ]; then
        echo -e "\033[0;31m[ERROR]\033[0m $1"
    else
        echo "[ERROR] $1"
    fi
}

# 生成随机字符串
generate_random_string() {
    length=${1:-12}
    openssl rand -base64 $length | tr -d "=+/" | cut -c1-$length
}

# 生成唯一ID
generate_config_id() {
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local random_str=$(generate_random_string 6)
    echo "${timestamp}_${random_str}"
}

# 初始化配置目录
init_config_dir() {
    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
        print_info "创建配置目录: $CONFIG_DIR"
    fi

    if [ ! -f "$META_FILE" ]; then
        cat > "$META_FILE" << 'EOF'
{
  "configs": [],
  "next_id": 1
}
EOF
        print_info "创建元数据文件: $META_FILE"
    fi
}

# 生成配置ID
get_next_config_id() {
    init_config_dir
    local next_id=$(jq -r '.next_id' "$META_FILE" 2>/dev/null || echo 1)
    echo "$next_id"
    # 更新next_id
    jq --argjson next_id "$((next_id + 1))" '.next_id = $next_id' "$META_FILE" > "${META_FILE}.tmp" && mv "${META_FILE}.tmp" "$META_FILE"
}

# 保存配置元数据
save_config_metadata() {
    local config_id=$1
    local network=$2
    local port=$3
    local username=$4
    local password=$5
    local config_dir=$6
    local timestamp=$(date -Iseconds 2>/dev/null || date +"%Y-%m-%dT%H:%M:%S")

    # 处理多选IP的网络描述
    local network_display="$network"
    if [[ "$network" == MULTI_IPS:* ]]; then
        local count=$(echo "$network" | cut -d':' -f2)
        network_display="多选IP ($count个)"
    fi

    # 使用jq构建JSON以确保正确的转义
    jq --arg id "$config_id" \
       --arg network "$network_display" \
       --arg port "$port" \
       --arg username "$username" \
       --arg password "$password" \
       --arg config_dir "$config_dir" \
       --arg timestamp "$timestamp" \
       '.configs += [{
         "id": ($id | tonumber),
         "network": $network,
         "port": ($port | tonumber),
         "username": $username,
         "password": $password,
         "config_dir": $config_dir,
         "created_at": $timestamp,
         "status": "created"
       }]' "$META_FILE" > "${META_FILE}.tmp" && mv "${META_FILE}.tmp" "$META_FILE"
}

# 检查网段和端口是否已存在
check_duplicate_config() {
    local network=$1
    local port=$2

    init_config_dir

    # 处理多选IP的网络显示名称
    local network_display="$network"
    if [[ "$network" == MULTI_IPS:* ]]; then
        local count=$(echo "$network" | cut -d':' -f2)
        network_display="多选IP ($count个)"
    fi

    # 检查是否有相同网段和端口的配置
    local existing=$(jq -r --arg network "$network_display" --arg port "$port" \
        '.configs[] | select(.network == $network and (.port | tostring) == $port) | .id' \
        "$META_FILE" 2>/dev/null)

    if [ -n "$existing" ]; then
        return 0  # 存在重复
    else
        return 1  # 不存在重复
    fi
}

# 检查配置是否正在运行
is_config_running() {
    local config_id=$1

    local config_info=$(jq -r ".configs[] | select(.id == $config_id)" "$META_FILE" 2>/dev/null)
    if [ -z "$config_info" ]; then
        return 1
    fi

    local config_dir=$(echo "$config_info" | jq -r '.config_dir')
    local pid_file="$config_dir/gost.pid"

    if [ ! -f "$pid_file" ]; then
        return 1
    fi

    local pid=$(cat "$pid_file")
    if ps -p "$pid" > /dev/null 2>&1; then
        return 0  # 正在运行
    else
        return 1  # 未运行
    fi
}

# 列出所有配置
list_configs() {
    init_config_dir
    local configs=$(jq -r '.configs[] | "\(.id):\(.network):\(.port):\(.created_at)"' "$META_FILE" 2>/dev/null)

    if [ -z "$configs" ]; then
        print_info "暂无配置"
        return 1
    fi

    echo ""
    print_info "=== 可用的配置 ==="
    echo "$configs" | while IFS=':' read -r id network port created_at; do
        if is_config_running "$id"; then
            if [ -t 1 ]; then
                echo -e "  $id: $network:$port \033[0;32m[运行中]\033[0m ($created_at)"
            else
                echo "  $id: $network:$port [运行中] ($created_at)"
            fi
        else
            if [ -t 1 ]; then
                echo -e "  $id: $network:$port \033[0;31m[已停止]\033[0m ($created_at)"
            else
                echo "  $id: $network:$port [已停止] ($created_at)"
            fi
        fi
    done
    echo ""
}

# 删除指定ID的配置
delete_config_by_id() {
    local config_id=$1

    if ! jq -e ".configs[] | select(.id == $config_id)" "$META_FILE" >/dev/null 2>&1; then
        print_error "配置ID $config_id 不存在"
        return 1
    fi

    local config_info=$(jq -r ".configs[] | select(.id == $config_id)" "$META_FILE")
    local config_dir=$(echo "$config_info" | jq -r '.config_dir')
    local network=$(echo "$config_info" | jq -r '.network')
    local port=$(echo "$config_info" | jq -r '.port')

    echo ""
    print_warning "即将删除配置:"
    print_info "  配置ID: $config_id"
    print_info "  网段: $network"
    print_info "  端口: $port"
    print_info "  配置目录: $config_dir"
    echo ""
    read -p "确认删除? (y/N): " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "取消删除"
        return 0
    fi

    # 检查并关闭运行中的进程
    local pid_file="$config_dir/gost.pid"
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p "$pid" > /dev/null 2>&1; then
            print_info "正在关闭运行中的GOST进程 (PID: $pid)..."
            kill "$pid" 2>/dev/null
            sleep 1
            # 如果进程还在运行，强制关闭
            if ps -p "$pid" > /dev/null 2>&1; then
                print_warning "进程未响应，强制关闭..."
                kill -9 "$pid" 2>/dev/null
            fi
            print_success "GOST进程已关闭"
        fi
    fi

    # 从元数据中删除配置
    jq --argjson id "$config_id" 'del(.configs[] | select(.id == $id))' "$META_FILE" > "${META_FILE}.tmp" && mv "${META_FILE}.tmp" "$META_FILE"

    # 删除配置目录
    if [ -d "$config_dir" ]; then
        rm -rf "$config_dir"
        print_success "配置目录已删除: $config_dir"
    fi

    print_success "配置ID $config_id 已删除"
}

# 关闭指定ID的代理
stop_proxy_by_id() {
    local config_id=$1

    if ! jq -e ".configs[] | select(.id == $config_id)" "$META_FILE" >/dev/null 2>&1; then
        print_error "配置ID $config_id 不存在"
        return 1
    fi

    local config_info=$(jq -r ".configs[] | select(.id == $config_id)" "$META_FILE")
    local config_dir=$(echo "$config_info" | jq -r '.config_dir')
    local pid_file="$config_dir/gost.pid"
    local config_file="$config_dir/gost-config.json"

    # 尝试多种方法找到并关闭GOST进程
    local found_processes=false

    # 方法1: 使用PID文件
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p "$pid" > /dev/null 2>&1; then
            print_info "发现GOST进程 (PID: $pid)，正在关闭..."
            kill "$pid" 2>/dev/null
            sleep 2
            found_processes=true
        else
            print_warning "PID文件中的进程 (PID: $pid) 未运行"
        fi
    else
        print_warning "PID文件不存在"
    fi

    # 方法2: 通过配置文件查找进程
    if ! $found_processes || [ ! -f "$pid_file" ]; then
        print_info "通过配置文件查找GOST进程..."
        local pids=$(pgrep -f "gost.*$config_file" 2>/dev/null)
        if [ -n "$pids" ]; then
            for pid in $pids; do
                if ps -p "$pid" > /dev/null 2>&1; then
                    print_info "发现GOST进程 (PID: $pid)，正在关闭..."
                    kill "$pid" 2>/dev/null
                    found_processes=true
                fi
            done
        fi
    fi

    # 方法3: 通过端口查找进程（如果知道端口）
    if ! $found_processes; then
        print_info "通过端口查找GOST进程..."
        # 从配置文件中提取端口信息
        local ports=$(grep -o '"addr":[[:space:]]*"[^"]*:[0-9]*"' "$config_file" 2>/dev/null | grep -o '[0-9]*$' | head -5)
        if [ -n "$ports" ]; then
            for port in $ports; do
                local pids=$(lsof -ti :"$port" 2>/dev/null)
                if [ -n "$pids" ]; then
                    for pid in $pids; do
                        if ps -p "$pid" > /dev/null 2>&1 && ps -p "$pid" -o comm= | grep -q "gost"; then
                            print_info "发现监听端口 $port 的GOST进程 (PID: $pid)，正在关闭..."
                            kill "$pid" 2>/dev/null
                            found_processes=true
                        fi
                    done
                fi
            done
        fi
    fi

    if ! $found_processes; then
        print_warning "未找到运行中的GOST进程"
        rm -f "$pid_file"
        # 更新状态
        jq --argjson id "$config_id" '.configs |= map(if .id == $id then .status = "stopped" else . end)' "$META_FILE" > "${META_FILE}.tmp" && mv "${META_FILE}.tmp" "$META_FILE"
        return 1
    fi

    # 等待进程优雅关闭
    sleep 2

    # 检查是否还有进程在运行，如果有则强制关闭
    local still_running=false
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p "$pid" > /dev/null 2>&1; then
            print_warning "进程未响应，强制关闭..."
            kill -9 "$pid" 2>/dev/null
            still_running=true
        fi
    fi

    # 再次检查通过配置文件找到的进程
    local pids=$(pgrep -f "gost.*$config_file" 2>/dev/null)
    if [ -n "$pids" ]; then
        for pid in $pids; do
            if ps -p "$pid" > /dev/null 2>&1; then
                print_warning "强制关闭进程 (PID: $pid)..."
                kill -9 "$pid" 2>/dev/null
                still_running=true
            fi
        done
    fi

    # 最终验证
    sleep 1
    local any_running=false
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p "$pid" > /dev/null 2>&1; then
            any_running=true
        fi
    fi

    if [ -n "$(pgrep -f "gost.*$config_file" 2>/dev/null)" ]; then
        any_running=true
    fi

    if $any_running; then
        print_error "无法完全关闭某些GOST进程，请手动检查"
        return 1
    else
        rm -f "$pid_file"
        print_success "所有GOST进程已关闭"
        # 更新状态
        jq --argjson id "$config_id" '.configs |= map(if .id == $id then .status = "stopped" else . end)' "$META_FILE" > "${META_FILE}.tmp" && mv "${META_FILE}.tmp" "$META_FILE"
        return 0
    fi
}

# 选择配置关闭菜单
select_config_to_stop() {
    if ! list_configs; then
        return 1
    fi

    echo ""
    print_info "请输入要关闭的配置ID，或输入 'q' 退出:"
    while true; do
        read -p "配置ID: " input

        if [ "$input" = "q" ] || [ "$input" = "Q" ]; then
            print_info "退出关闭菜单"
            return 0
        fi

        if echo "$input" | grep -qE '^[0-9]+$'; then
            if stop_proxy_by_id "$input"; then
                break
            fi
        else
            print_warning "请输入有效的数字ID"
        fi
    done

    echo ""
    read -p "按回车键继续..." -r
}

# 选择配置删除菜单
select_config_to_delete() {
    if ! list_configs; then
        return 1
    fi

    echo ""
    print_info "请输入要删除的配置ID，或输入 'q' 退出:"
    while true; do
        read -p "配置ID: " input

        if [ "$input" = "q" ] || [ "$input" = "Q" ]; then
            print_info "退出删除菜单"
            return 0
        fi

        if echo "$input" | grep -qE '^[0-9]+$'; then
            if delete_config_by_id "$input"; then
                break
            fi
        else
            print_warning "请输入有效的数字ID"
        fi
    done

    echo ""
    read -p "按回车键继续..." -r
}

# 启动指定ID的代理
start_proxy_by_id() {
    local config_id=$1

    if ! jq -e ".configs[] | select(.id == $config_id)" "$META_FILE" >/dev/null 2>&1; then
        print_error "配置ID $config_id 不存在"
        return 1
    fi

    # 检查是否已经在运行
    if is_config_running "$config_id"; then
        print_warning "配置ID $config_id 的代理已经在运行中"
        local config_info=$(jq -r ".configs[] | select(.id == $config_id)" "$META_FILE")
        local config_dir=$(echo "$config_info" | jq -r '.config_dir')
        local pid_file="$config_dir/gost.pid"
        local pid=$(cat "$pid_file")
        print_info "进程PID: $pid"
        return 1
    fi

    local config_info=$(jq -r ".configs[] | select(.id == $config_id)" "$META_FILE")
    local config_dir=$(echo "$config_info" | jq -r '.config_dir')
    local config_file="$config_dir/gost-config.json"

    if [ ! -f "$config_file" ]; then
        print_error "配置文件不存在: $config_file"
        return 1
    fi

    print_info "启动配置ID $config_id 的代理服务器..."
    print_info "配置文件: $config_file"

    # 更新状态为运行中
    jq --argjson id "$config_id" '.configs |= map(if .id == $id then .status = "running" else . end)' "$META_FILE" > "${META_FILE}.tmp" && mv "${META_FILE}.tmp" "$META_FILE"

    # 启动GOST，使用nohup并输出日志
    local log_file="$config_dir/gost.log"
    local pid_file="$config_dir/gost.pid"

    # 确保旧的进程已经停止
    if [ -f "$pid_file" ]; then
        local old_pid=$(cat "$pid_file")
        if ps -p "$old_pid" > /dev/null 2>&1; then
            print_info "发现旧的进程正在运行 (PID: $old_pid)，正在停止..."
            kill "$old_pid" 2>/dev/null
            sleep 2
            if ps -p "$old_pid" > /dev/null 2>&1; then
                print_warning "强制停止旧进程..."
                kill -9 "$old_pid" 2>/dev/null
            fi
        fi
    fi

    # 使用nohup和setsid确保进程完全独立
    print_info "启动GOST代理服务..."
    print_info "配置文件: $config_file"

    # 使用setsid创建新的会话，确保进程完全独立
    nohup setsid gost -C "$config_file" > "$log_file" 2>&1 &
    local gost_pid=$!

    # 等待一下确保进程启动
    sleep 1

    # 验证进程是否真的启动了
    if ps -p "$gost_pid" > /dev/null 2>&1; then
        # 保存PID到文件
        echo "$gost_pid" > "$pid_file"

        print_success "GOST代理服务已启动，PID: $gost_pid"
        print_info "日志文件: $log_file"
        print_info "PID文件: $pid_file"
        print_info "查看日志: tail -f $log_file"
        print_info "停止服务: ./generate-socks5.sh -k $config_id"

        # 检查进程是否正常监听端口
        sleep 2
        local listening_count=$(netstat -tlnp 2>/dev/null | grep "$gost_pid/gost" | wc -l)
        if [ "$listening_count" -gt 0 ]; then
            print_success "代理服务正在监听 $listening_count 个端口"
        else
            print_warning "未检测到代理服务监听端口，请检查日志文件"
        fi
    else
        print_error "GOST启动失败，请检查配置文件和日志"
        if [ -f "$log_file" ]; then
            print_info "错误日志:"
            tail -10 "$log_file"
        fi
        return 1
    fi

    # 显示代理信息
    local results_file="$config_dir/socks5_results.txt"
    if [ -f "$results_file" ]; then
        echo ""
        print_info "=== 代理列表 (host:port:username:password) ==="
        cat "$results_file"
        echo ""
        print_success "共 $(cat "$results_file" | wc -l) 个代理"
    fi

    echo ""
    read -p "按回车键继续..." -r
}

# 选择配置菜单
select_config_to_start() {
    if ! list_configs; then
        return 1
    fi

    echo ""
    print_info "请输入要启动的配置ID，或输入 'q' 退出:"
    while true; do
        read -p "配置ID: " input

        if [ "$input" = "q" ] || [ "$input" = "Q" ]; then
            print_info "退出启动菜单"
            return 0
        fi

        if echo "$input" | grep -qE '^[0-9]+$'; then
            if start_proxy_by_id "$input"; then
                break
            fi
        else
            print_warning "请输入有效的数字ID"
        fi
    done
}

# 获取本机网络接口和IP地址
get_network_interfaces() {
    print_info "正在获取本机网络接口..."

    if command -v ip >/dev/null 2>&1; then
        # Linux
        ip addr show | grep -E "inet.*scope global" | awk '{print $2}' | cut -d'/' -f1
    elif command -v ifconfig >/dev/null 2>&1; then
        # macOS
        ifconfig | grep -E "inet.*broadcast" | awk '{print $2}'
    else
        print_error "无法获取网络接口信息，请确保系统安装了 ip 或 ifconfig 命令"
        exit 1
    fi
}

# 获取路由网段信息
get_route_networks() {
    print_info "正在获取路由网段信息..."

    local networks=()

    if command -v ip >/dev/null 2>&1; then
        # Linux - 使用 ip route 获取路由信息
        # 获取直连路由网段
        while IFS= read -r line; do
            if echo "$line" | grep -q "dev"; then
                local network=$(echo "$line" | awk '{print $1}')
                # 排除默认路由和环回路由
                if [[ "$network" != "default" && "$network" != "127.0.0.0/8" && "$network" != "::/128" ]]; then
                    # 确保是IPv4网段格式
                    if echo "$network" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$"; then
                        networks+=("$network")
                    fi
                fi
            fi
        done < <(ip route show)
    elif command -v netstat >/dev/null 2>&1; then
        # macOS 或其他系统 - 使用 netstat
        while IFS= read -r line; do
            if echo "$line" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+"; then
                local network=$(echo "$line" | awk '{print $1}')
                # 排除环回路由
                if [[ "$network" != "127.0.0.0/8" ]]; then
                    networks+=("$network")
                fi
            fi
        done < <(netstat -rn | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+")
    fi

    # 如果没有找到路由网段，回退到获取IP地址
    if [ ${#networks[@]} -eq 0 ]; then
        print_warning "未找到路由网段信息，回退到获取IP地址"
        local ips=($(get_network_interfaces))
        for ip in "${ips[@]}"; do
            # 将IP转换为/24网段
            local base_ip=$(echo "$ip" | cut -d'.' -f1-3)
            networks+=("${base_ip}.0/24")
        done
    fi

    # 去重
    printf '%s\n' "${networks[@]}" | sort -u
}

# 验证网段格式
validate_network() {
    local network=$1

    # 检查单个IP格式
    if echo "$network" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"; then
        return 0
    fi

    # 检查CIDR格式
    if echo "$network" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$"; then
        local ip=$(echo "$network" | cut -d'/' -f1)
        local cidr=$(echo "$network" | cut -d'/' -f2)

        # 验证CIDR范围
        if [ "$cidr" -ge 0 ] && [ "$cidr" -le 32 ]; then
            return 0
        fi
    fi

    return 1
}

# 获取指定网段的所有IP地址
get_network_range() {
    local network=$1

    # 检查是否为多选IP标记
    if [[ "$network" == MULTI_IPS:* ]]; then
        # 解析多选IP标记: MULTI_IPS:count:ip1 ip2 ip3...
        local count=$(echo "$network" | cut -d':' -f2)
        local ips=$(echo "$network" | cut -d':' -f3-)

        print_info "多选IP模式，将为 $count 个选择的IP生成代理" >&2

        # 输出所有选择的IP地址，每行一个
        for ip in $ips; do
            echo "$ip"
        done
        return 0
    fi

    # 检查是否为单个IP格式（不包含斜杠）
    if [[ ! "$network" == *"/"* ]]; then
        # 单个IP，直接返回该IP
        print_info "单个IP模式，仅生成1个代理" >&2
        echo "$network"
        return 0
    fi

    # CIDR 格式处理
    local base_ip=$(echo $network | cut -d'.' -f1-3)
    local cidr=$(echo $network | cut -d'/' -f2)

    # 计算可用主机数量
    if [ "$cidr" -ge 24 ]; then
        # 对于 /24 或更大的网段，生成主机地址
        local host_bits=$((32 - cidr))
        local host_count=$((2 ** host_bits - 2))

        # 限制最大数量
        if [ $host_count -gt 254 ]; then
            host_count=254
        fi

        # 对于 /24，只生成 1-254
        if [ "$cidr" -eq 24 ]; then
            for i in $(seq 1 254); do
                echo "${base_ip}.$i"
            done
        else
            # 对于大于 /24 的网段，生成计算出的主机数量
            local start_ip=1
            local end_ip=$((host_count))
            for i in $(seq $start_ip $end_ip); do
                echo "${base_ip}.$i"
            done
        fi
    else
        # 对于小于 /24 的网段，只生成网络中的几个IP用于测试
        print_warning "网段 $network 范围太大，仅生成前10个IP用于测试" >&2
        for i in $(seq 1 10); do
            echo "${base_ip}.$i"
        done
    fi
}

# 生成GOST配置JSON
generate_gost_config() {
    local port=$1
    local unified_username=$2
    local unified_password=$3
    local config_id=$4
    shift 4
    local ip_list=("$@")

    local config_dir="$CONFIG_DIR/config_$config_id"
    mkdir -p "$config_dir"
    local config_file="$config_dir/gost-config.json"
    local results_file="$config_dir/socks5_results.txt"

    # 开始生成JSON配置
    cat > $config_file << 'EOF'
{
  "services": [
EOF

    local services=""
    local authers=""

    # 判断是否使用统一认证
    if [ -n "$unified_username" ] && [ -n "$unified_password" ]; then
        # 使用统一的认证器
        local auther_name="unified-auther"

        # 生成统一auther配置
        authers=$(cat << EOF
{
      "name": "$auther_name",
      "auths": [
        {
          "username": "$unified_username",
          "password": "$unified_password"
        }
      ]
    }
EOF
        )

        for ip in "${ip_list[@]}"; do
            local service_name="service-${ip//./-}-$port"

            # 生成service配置
            if [ -n "$services" ]; then
                services+=",\n    "
            fi

            services+=$(cat << EOF
{
      "name": "$service_name",
      "addr": "$ip:$port",
      "handler": {
        "type": "auto",
        "auther": "$auther_name",
        "metadata": {
          "bind": true,
          "udp": true
        }
      },
      "listener": {
        "type": "tcp"
      },
      "metadata": {
        "enableStats": "true",
        "interface": "$ip"
      }
    }
EOF
            )

            # 输出连接信息到结果文件
            echo "${ip}:${port}:${unified_username}:${unified_password}" >> "$results_file"
        done
    else
        # 为每个IP生成独立的认证器
        for ip in "${ip_list[@]}"; do
            local service_name="service-${ip//./-}-$port"
            local auther_name="auther-${ip//./-}-$port"
            local username=$(generate_random_string 12)
            local password=$(generate_random_string 12)

                  # 生成service配置
            if [ -n "$services" ]; then
                services+=",\n    "
            fi

            services+=$(cat << EOF
{
      "name": "$service_name",
      "addr": "$ip:$port",
      "handler": {
        "type": "auto",
        "auther": "$auther_name",
        "metadata": {
          "bind": true,
          "udp": true
        }
      },
      "listener": {
        "type": "tcp"
      },
      "metadata": {
        "enableStats": "true",
        "interface": "$ip"
      }
    }
EOF
            )

            # 生成auther配置
            if [ -n "$authers" ]; then
                authers+=",\n    "
            fi

            authers+=$(cat << EOF
{
      "name": "$auther_name",
      "auths": [
        {
          "username": "$username",
          "password": "$password"
        }
      ]
    }
EOF
            )

            # 输出连接信息到结果文件
            echo "${ip}:${port}:${username}:${password}" >> "$results_file"
        done
    fi

    # 完成services部分
    echo -e "$services" >> $config_file
    cat >> $config_file << 'EOF'
  ],
  "authers": [
EOF

    # 添加authers部分
    echo -e "$authers" >> $config_file
    cat >> $config_file << 'EOF'
  ]
}
EOF

    print_success "GOST配置文件已生成: $config_file" >&2
    print_info "连接信息已保存到: $results_file" >&2
    print_info "配置ID: $config_id" >&2

    # 返回配置目录路径供主函数使用
    echo "$config_dir"
}

# 网段选择菜单
select_network() {
    while true; do
        echo "" >&2
        echo "请选择网段来源:" >&2
        echo "1) 从路由表中选择网段 (推荐)" >&2
        echo "2) 从本机IP地址中选择 (支持多选)" >&2
        echo "3) 手动输入网段或IP (CIDR网段或单个IP)" >&2
        echo "4) 退出" >&2
        echo "" >&2
        echo -n "请输入选择 (1-4): " >&2
        read choice
        case $choice in
            1)
                select_route_network
                return $?
                ;;
            2)
                select_interface_ip
                return $?
                ;;
            3)
                input_manual_network
                return $?
                ;;
            4)
                print_info "操作已取消" >&2
                exit 0
                ;;
            *)
                print_warning "无效选择，请输入 1-4" >&2
                ;;
        esac
    done
}

# 从路由表中选择网段
select_route_network() {
    echo "" >&2
    print_info "可用的路由网段:" >&2
    local networks=($(get_route_networks 2>&2))

    if [ ${#networks[@]} -eq 0 ]; then
        print_error "未找到可用的路由网段" >&2
        return 1
    fi

    # 使用select命令显示选择菜单
    PS3="请选择路由网段 (输入数字): "
    select selected_network in "${networks[@]}" "返回上级菜单"; do
        if [ -n "$selected_network" ]; then
            if [ "$selected_network" = "返回上级菜单" ]; then
                select_network
                return $?
            else
                # 显示选择的网段信息
                print_info "选择的网段: $selected_network" >&2
                echo "$selected_network"
                return 0
            fi
        else
            print_warning "无效选择，请重新输入" >&2
        fi
    done
}

# 从本机IP地址中选择 (支持多选)
select_interface_ip() {
    echo "" >&2
    print_info "可用的网络接口IP地址:" >&2
    local interfaces=($(get_network_interfaces 2>&2))

    if [ ${#interfaces[@]} -eq 0 ]; then
        print_error "未找到可用的网络接口" >&2
        return 1
    fi

    # 显示所有可用IP
    echo "" >&2
    for i in "${!interfaces[@]}"; do
        echo "  $((i+1)). ${interfaces[$i]}" >&2
    done
    echo "" >&2

    local selected_ips=()

    while true; do
        echo "" >&2
        print_info "请选择IP地址 (输入数字，多个用空格分隔，0 结束选择):" >&2
        read -p "选择: " input

        if [ "$input" = "0" ]; then
            if [ ${#selected_ips[@]} -eq 0 ]; then
                print_warning "未选择任何IP地址" >&2
                continue
            else
                break
            fi
        fi

        # 解析输入的数字
        local valid_selection=true
        for num in $input; do
            if echo "$num" | grep -qE '^[0-9]+$'; then
                if [ "$num" -ge 1 ] && [ "$num" -le ${#interfaces[@]} ]; then
                    local selected_ip="${interfaces[$((num-1))]}"
                    # 检查是否已经选择过
                    if [[ ! " ${selected_ips[@]} " =~ " ${selected_ip} " ]]; then
                        selected_ips+=("$selected_ip")
                        print_success "已添加: $selected_ip" >&2
                    else
                        print_warning "$selected_ip 已选择" >&2
                    fi
                else
                    print_warning "数字 $num 超出范围" >&2
                    valid_selection=false
                fi
            else
                print_warning "'$num' 不是有效数字" >&2
                valid_selection=false
            fi
        done

        if [ "$valid_selection" = true ]; then
            echo "" >&2
            print_info "当前已选择的IP地址:" >&2
            for ip in "${selected_ips[@]}"; do
                echo "  - $ip" >&2
            done
        fi
    done

    echo "" >&2
    print_info "最终选择了 ${#selected_ips[@]} 个IP地址:" >&2
    for ip in "${selected_ips[@]}"; do
        echo "  - $ip" >&2
    done

    # 返回特殊格式的字符串，类似全部IP的处理方式
    echo "MULTI_IPS:${#selected_ips[@]}:${selected_ips[*]}"
    return 0
}

# 手动输入网段
input_manual_network() {
    echo "" >&2
    print_info "请输入网段或IP地址" >&2
    print_info "支持格式:" >&2
    print_info "  - CIDR网段: 192.168.1.0/24" >&2
    print_info "  - 单个IP: 192.168.1.100" >&2
    echo "" >&2

    while true; do
        echo "" >&2
        print_info "请输入网段或IP地址:" >&2
        read manual_network

        # 验证输入
        if validate_network "$manual_network"; then
            # 如果是单个IP，直接使用该IP
            if echo "$manual_network" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"; then
                print_info "将仅对IP $manual_network 生成代理" >&2
                echo "$manual_network"
                return 0
            else
                # CIDR网段，直接使用
                echo "$manual_network"
                return 0
            fi
        else
            print_warning "无效的网段格式，请重新输入" >&2
            print_info "示例: 192.168.1.0/24 或 10.0.0.100" >&2
        fi
    done
}

# 生成新配置的函数
generate_new_config() {
    local port=8080
    local network=""
    local unified_username=""
    local unified_password=""

    echo ""
    print_info "=== 生成新的SOCKS5代理配置 ==="
    echo ""

    # 获取端口
    print_info "请输入SOCKS5端口 (默认8080):"
    read -p "端口: " input_port
    if [ -n "$input_port" ]; then
        port="$input_port"
    fi

    # 询问是否使用统一认证
    echo ""
    print_info "是否使用统一认证?"
    read -p "选择 (y/N): " use_unified
    if [[ $use_unified =~ ^[Yy]$ ]]; then
        echo ""
        print_info "请输入认证信息:"
        read -p "用户名: " unified_username
        read -s -p "密码: " unified_password
        echo ""
    fi

    # 选择网段
    network=$(select_network)
    if [ $? -ne 0 ]; then
        print_error "网段选择失败"
        return 1
    fi

    # 处理多选IP的显示
    local network_display="$network"
    if [[ "$network" == MULTI_IPS:* ]]; then
        local count=$(echo "$network" | cut -d':' -f2)
        network_display="多选IP ($count个)"
    fi

    print_info "选择的网段: $network_display"
    print_info "SOCKS5端口: $port"

    if [ -n "$unified_username" ]; then
        print_info "使用统一认证: 用户名=$unified_username"
    else
        print_info "使用随机认证信息"
    fi

    # 生成IP列表
    print_info "正在生成IP地址列表..."
    local ip_list_str=$(get_network_range "$network")
    local ip_list=($ip_list_str)

    if [ ${#ip_list[@]} -eq 0 ]; then
        print_error "无法从网段 $network 生成IP地址"
        return 1
    fi

    print_info "将生成 ${#ip_list[@]} 个SOCKS5代理"

    # 检查是否已存在相同的配置
    if check_duplicate_config "$network" "$port"; then
        echo ""
        print_error "配置已存在！"
        print_warning "网段 $network 和端口 $port 的配置已经存在"

        # 显示已存在的配置
        local existing_id=$(jq -r --arg network "$network" --arg port "$port" \
            '.configs[] | select(.network == $network and (.port | tostring) == $port) | .id' \
            "$META_FILE" 2>/dev/null)

        if [ -n "$existing_id" ]; then
            print_info "已存在的配置ID: $existing_id"
            local existing_config=$(jq -r ".configs[] | select(.id == $existing_id)" "$META_FILE")
            local existing_dir=$(echo "$existing_config" | jq -r '.config_dir')
            print_info "配置目录: $existing_dir"
        fi

        echo ""
        print_info "如果需要重新创建，请先删除已有配置"
        echo ""
        read -p "按回车键继续..." -r
        return 1
    fi

    # 确认继续
    echo ""
    print_info "确认生成SOCKS5代理配置?"
    read -p "继续吗? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "操作已取消"
        return 0
    fi

    # 初始化配置目录
    init_config_dir

    # 获取配置ID
    local config_id=$(get_next_config_id)

    # 生成配置文件
    print_info "正在生成GOST配置文件..."
    local config_dir=$(generate_gost_config "$port" "$unified_username" "$unified_password" "$config_id" "${ip_list[@]}")

    # 保存元数据
    save_config_metadata "$config_id" "$network" "$port" "$unified_username" "$unified_password" "$config_dir"

    # 显示结果
    print_success "SOCKS5代理配置生成完成!"
    print_info "配置ID: $config_id"
    print_info "配置目录: $config_dir"
    echo ""

    # 显示代理列表
    local results_file="$config_dir/socks5_results.txt"
    if [ -f "$results_file" ]; then
        print_info "=== 代理列表 (host:port:username:password) ==="
        cat "$results_file"
        echo ""
        print_success "共 $(cat "$results_file" | wc -l) 个代理已生成"
    fi

    echo ""
    print_info "启动代理命令:"
    print_info "./generate-socks5.sh -s $config_id"
    print_info "或者直接运行: gost -C $config_dir/gost-config.json"
    echo ""

    read -p "按回车键继续..." -r
}

# 主菜单
show_main_menu() {
    clear
    echo ""
    print_info "=== GOST SOCKS5 批量管理工具 ==="
    echo "1) 生成新的SOCKS5代理配置"
    echo "2) 启动已有配置的代理"
    echo "3) 关闭已有配置的代理"
    echo "4) 查看所有配置"
    echo "5) 删除指定配置"
    echo "6) 显示网络接口信息"
    echo "7) 退出"
    echo ""
}

# 显示使用说明
show_usage() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help              显示此帮助信息"
    echo "  -p, --port PORT         指定SOCKS5端口 (默认: 8080)"
    echo "  -n, --network NET       指定网段 (例如: 192.168.1.0/24)"
    echo "  -u, --username USER     指定统一的用户名"
    echo "  -P, --password PASS     指定统一的密码"
    echo "  -i, --interface         显示可用的网络接口和路由网段"
    echo "  -s, --start-id ID       直接启动指定ID的代理"
    echo "  -k, --stop-id ID        关闭指定ID的代理"
    echo "  -d, --delete-id ID      删除指定ID的配置"
    echo "  -l, --list              列出所有配置"
    echo ""
    echo "示例:"
    echo "  $0 -p 1080 -n 192.168.1.0/24"
    echo "  $0 --port 8080 --network 10.0.0.0/24 -u myuser -P mypass"
    echo "  $0 -n 192.168.1.0/24 -u admin -P password123"
    echo "  $0 -u myuser -P mypass  # 交互式选择网段"
    echo "  $0 -s 1                 # 启动ID为1的配置"
    echo "  $0 -k 1                 # 关闭ID为1的代理"
    echo "  $0 -d 1                 # 删除ID为1的配置"
    echo "  $0 -l                   # 列出所有配置"
    echo ""
    echo "说明:"
    echo "  - 如果指定了用户名和密码，所有代理将使用统一的认证信息"
    echo "  - 如果未指定，每个代理将生成独立的随机用户名密码"
    echo "  - 如果未指定网段(-n)，将进入交互式选择模式"
    echo "  - 选择本机IP时，支持多选多个IP地址"
    echo "  - 选择网段时，将对整个网段生成代理"
    echo "  - 配置文件保存在 $CONFIG_DIR/ 目录下，每个配置有唯一ID"
}

# 主函数
main() {
    local port=8080
    local network=""
    local unified_username=""
    local unified_password=""
    local show_interfaces=false
    local start_id=""
    local stop_id=""
    local delete_id=""
    local list_configs=false
    local interactive_mode=false

    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -p|--port)
                port="$2"
                shift 2
                ;;
            -n|--network)
                network="$2"
                shift 2
                ;;
            -u|--username)
                unified_username="$2"
                shift 2
                ;;
            -P|--password)
                unified_password="$2"
                shift 2
                ;;
            -i|--interface)
                show_interfaces=true
                shift
                ;;
            -s|--start-id)
                start_id="$2"
                shift 2
                ;;
            -k|--stop-id)
                stop_id="$2"
                shift 2
                ;;
            -d|--delete-id)
                delete_id="$2"
                shift 2
                ;;
            -l|--list)
                list_configs=true
                shift
                ;;
            *)
                if [ $# -eq 1 ] && [[ ! "$1" =~ ^- ]]; then
                    interactive_mode=true
                else
                    print_error "未知参数: $1"
                    show_usage
                    exit 1
                fi
                ;;
        esac
    done

    # 检查如果只提供了用户名或密码中的一个
    if { [ -n "$unified_username" ] && [ -z "$unified_password" ]; } || { [ -z "$unified_username" ] && [ -n "$unified_password" ]; }; then
        print_error "用户名和密码必须同时提供或同时省略"
        show_usage
        exit 1
    fi

    # 处理特殊操作模式
    if [ "$list_configs" = true ]; then
        list_configs
        exit $?
    fi

    if [ -n "$start_id" ]; then
        start_proxy_by_id "$start_id"
        exit $?
    fi

    if [ -n "$stop_id" ]; then
        stop_proxy_by_id "$stop_id"
        exit $?
    fi

    if [ -n "$delete_id" ]; then
        delete_config_by_id "$delete_id"
        exit $?
    fi

    # 如果没有参数，显示主菜单
    if [ $# -eq 0 ]; then
        while true; do
            show_main_menu
            echo ""
            print_info "请选择操作 (1-7):"
            read -p "选择: " choice

            case $choice in
                1)
                    generate_new_config
                    ;;
                2)
                    select_config_to_start
                    ;;
                3)
                    select_config_to_stop
                    ;;
                4)
                    list_configs
                    echo ""
                    read -p "按回车键继续..." -r
                    ;;
                5)
                    select_config_to_delete
                    ;;
                6)
                    echo ""
                    print_info "=== 路由网段信息 ==="
                    get_route_networks
                    echo ""
                    print_info "=== 本机IP地址 ==="
                    get_network_interfaces
                    echo ""
                    read -p "按回车键继续..." -r
                    ;;
                7)
                    print_info "退出程序"
                    exit 0
                    ;;
                *)
                    print_warning "无效选择，请输入 1-7"
                    ;;
            esac
        done
    fi

    # 处理传统命令行模式
    print_info "GOST SOCKS5 批量生成工具"
    print_info "=========================="

    # 显示可用接口
    if [ "$show_interfaces" = true ]; then
        echo ""
        print_info "=== 路由网段信息 ==="
        get_route_networks

        echo ""
        print_info "=== 本机IP地址 ==="
        get_network_interfaces
        exit 0
    fi

    # 检查gost是否安装
    if ! command -v gost >/dev/null 2>&1; then
        print_error "GOST 未安装，请先运行以下命令安装:"
        print_error "bash <(curl -fsSL https://github.com/go-gost/gost/raw/master/install.sh) --install"
        exit 1
    fi

    # 获取网络接口或网段
    if [ -n "$network" ]; then
        # 验证命令行指定的网段
        if ! validate_network "$network"; then
            print_error "无效的网段格式: $network"
            print_info "请使用正确的格式，如: 192.168.1.0/24 或 10.0.0.100"
            exit 1
        fi

        # 如果是单个IP，直接使用该IP
        if echo "$network" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"; then
            print_info "将仅对IP $network 生成代理"
        fi
    else
        # 交互式选择网段
        network=$(select_network)
        if [ $? -ne 0 ]; then
            print_error "网段选择失败"
            exit 1
        fi
    fi

    # 处理多选IP的显示
    local network_display="$network"
    if [[ "$network" == MULTI_IPS:* ]]; then
        local count=$(echo "$network" | cut -d':' -f2)
        network_display="多选IP ($count个)"
    fi

    print_info "选择的网段: $network_display"
    print_info "SOCKS5端口: $port"

    if [ -n "$unified_username" ]; then
        print_info "使用统一认证: 用户名=$unified_username"
    else
        print_info "使用随机认证信息"
    fi

    # 生成IP列表
    print_info "正在生成IP地址列表..."
    local ip_list_str=$(get_network_range "$network")
    local ip_list=($ip_list_str)

    if [ ${#ip_list[@]} -eq 0 ]; then
        print_error "无法从网段 $network 生成IP地址"
        exit 1
    fi

    print_info "将生成 ${#ip_list[@]} 个SOCKS5代理"

    # 检查是否已存在相同的配置
    if check_duplicate_config "$network" "$port"; then
        echo ""
        print_error "配置已存在！"
        print_warning "网段 $network 和端口 $port 的配置已经存在"

        # 显示已存在的配置
        local existing_id=$(jq -r --arg network "$network" --arg port "$port" \
            '.configs[] | select(.network == $network and (.port | tostring) == $port) | .id' \
            "$META_FILE" 2>/dev/null)

        if [ -n "$existing_id" ]; then
            print_info "已存在的配置ID: $existing_id"
            local existing_config=$(jq -r ".configs[] | select(.id == $existing_id)" "$META_FILE")
            local existing_dir=$(echo "$existing_config" | jq -r '.config_dir')
            print_info "配置目录: $existing_dir"
        fi

        echo ""
        print_info "如果需要重新创建，请先删除已有配置"
        exit 1
    fi

    # 确认继续
    echo ""
    print_info "确认生成SOCKS5代理配置?"
    read -p "继续吗? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "操作已取消"
        exit 0
    fi

    # 初始化配置目录
    init_config_dir

    # 获取配置ID
    local config_id=$(get_next_config_id)

    # 生成配置文件
    print_info "正在生成GOST配置文件..."
    local config_dir=$(generate_gost_config "$port" "$unified_username" "$unified_password" "$config_id" "${ip_list[@]}")

    # 保存元数据
    save_config_metadata "$config_id" "$network" "$port" "$unified_username" "$unified_password" "$config_dir"

    # 显示结果
    print_success "SOCKS5代理配置生成完成!"
    print_info "配置ID: $config_id"
    print_info "配置目录: $config_dir"
    print_info ""
    print_info "启动代理命令:"
    print_info "./generate-socks5.sh -s $config_id"
    print_info "或者直接运行: gost -C $config_dir/gost-config.json"
    print_info ""
    print_info "生成的SOCKS5代理列表 (host:port:username:password):"
    print_success "$(cat "$config_dir/socks5_results.txt" | wc -l) 个代理已生成"
}

# 运行主函数
main "$@"