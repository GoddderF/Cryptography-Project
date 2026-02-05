import json
import os
import sys
from paillier_core import PaillierCipher

# --- 文件配置 ---
PUB_KEY_FILE = "network_public_key.json"
PRIV_KEY_FILE = "offline_private_key.json"
BALLOT_BOX_FILE = "network_ballot_box.json"
RESULT_FILE = "network_encrypted_result.json"
CONFIG_FILE = "election_config.json"  # 新增：存储候选人名单

# --- 核心参数 ---
# 每个候选人预留的位数基数。
# 1000 代表每个候选人最多可以接受 999 票而不发生进位溢出。
# 原理：Vote_Value = SLOT_SIZE ^ (Candidate_Index)
SLOT_SIZE = 1000


def clean_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def save_json(filename, data):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"  [存储] 数据已更新至 {filename}")


def load_json(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"\n[错误] 找不到文件 {filename}。请按照步骤顺序执行程序。")
        return None


# --- Step 0: 配置选举 (定义候选人) ---
def configure_election():
    clean_screen()
    print("=== Step 0: 选举参数配置 (Admin) ===")
    print("在此步骤，我们将定义本次选举的候选人名单。\n")

    candidates = []
    max_candidates = 5  # 你可以在这里设定最大数量限制

    print(f"请输入候选人姓名 (最多 {max_candidates} 人)。")
    print("直接按回车键结束录入。\n")

    while len(candidates) < max_candidates:
        name = input(f"请输入第 {len(candidates) + 1} 位候选人姓名: ").strip()
        if not name:
            if len(candidates) < 2:
                print("错误：至少需要 2 位候选人才能开始选举。")
                continue
            break
        candidates.append(name)
        print(f"  -> 已添加: {name}")

    config_data = {
        "candidates": candidates,
        "slot_size": SLOT_SIZE
    }
    save_json(CONFIG_FILE, config_data)

    print("\n[配置完成] 候选人名单已生成。")
    input("按回车键返回主菜单...")


# --- Step 1: 权威机构初始化 ---
def setup_election():
    clean_screen()
    print("=== Step 1: 权威机构初始化 (Trusted Authority) ===")

    # 检查是否已配置
    if not os.path.exists(CONFIG_FILE):
        print("错误：尚未配置候选人。请先执行 Step 0。")
        input("按回车返回...")
        return

    print("正在生成 Paillier 密钥对 (这可能需要几秒钟)...")
    # 生成密钥
    cipher = PaillierCipher(key_size=128, generate_keys=True)

    # 保存公钥
    save_json(PUB_KEY_FILE, {"n": cipher.n, "g": cipher.g})
    # 保存私钥
    save_json(PRIV_KEY_FILE, {"lam": cipher.lam, "mu": cipher.mu, "n": cipher.n})
    # 初始化空票箱
    save_json(BALLOT_BOX_FILE, [])

    print("\n[系统就绪] 密钥分发完毕，票箱已重置。")
    input("按回车键进入下一步：选民投票...")


# --- Step 2: 选民投票 (多选一逻辑) ---
def voter_action():
    clean_screen()
    print("=== Step 2: 选民客户端 (Voter Client) ===")

    pub_data = load_json(PUB_KEY_FILE)
    config = load_json(CONFIG_FILE)
    if not pub_data or not config: return

    candidates = config['candidates']

    # 重建只含公钥的 Cipher
    cipher = PaillierCipher(generate_keys=False)
    cipher.n = pub_data['n']
    cipher.g = pub_data['g']
    cipher.n_sq = cipher.n ** 2

    ballots = load_json(BALLOT_BOX_FILE)

    while True:
        print(f"\n当前票箱内已有 {len(ballots)} 张选票。")
        print("-" * 40)
        print("候选人名单:")
        for idx, name in enumerate(candidates):
            print(f"  [{idx}] {name}")
        print("-" * 40)

        choice = input("请输入候选人编号进行投票 (输入 'q' 结束并上传): ")
        if choice.lower() == 'q':
            break

        if not choice.isdigit():
            print("输入无效，请输入数字。")
            continue

        idx = int(choice)
        if idx < 0 or idx >= len(candidates):
            print("编号超出范围，请重试。")
            continue

        # === 核心：多路编码逻辑 ===
        # 选第0人 -> m = 1
        # 选第1人 -> m = 1000
        # 选第2人 -> m = 1000000
        m = pow(SLOT_SIZE, idx)

        print(f"正在加密选票 (对应明文数值: {m})...")
        c = cipher.encrypt(m)
        ballots.append(str(c))
        print("  -> 投票成功！密文已存入缓存。")

    save_json(BALLOT_BOX_FILE, ballots)
    print("\n[上传成功] 所有选票已同步至网络票箱。")
    input("按回车键进入下一步：云端计票...")


# --- Step 3: 云端计票 (不变，依然是纯加法) ---
def cloud_server_tally():
    clean_screen()
    print("=== Step 3: 云端计票服务器 (Untrusted Cloud) ===")

    pub_data = load_json(PUB_KEY_FILE)
    ballots = load_json(BALLOT_BOX_FILE)

    if not pub_data or not ballots:
        print("缺少数据，无法计票。")
        input("按回车返回...");
        return

    print(f"接收到 {len(ballots)} 张加密选票。")
    print("正在进行同态聚合 (Homomorphic Addition)...")

    cipher = PaillierCipher(generate_keys=False)
    cipher.n = pub_data['n']
    cipher.n_sq = cipher.n ** 2

    if len(ballots) == 0:
        encrypted_sum = 0  # 处理空票箱
    else:
        encrypted_sum = int(ballots[0])
        for i in range(1, len(ballots)):
            c_next = int(ballots[i])
            encrypted_sum = cipher.homomorphic_add(encrypted_sum, c_next)
            # 简单的进度条
            if i % 5 == 0: print(f"  ...处理进度: {i}/{len(ballots)}")

    print("\n[计算完成] 聚合密文已生成。")
    print(f"密文片段: {str(encrypted_sum)[:30]}...")

    save_json(RESULT_FILE, {"encrypted_sum": str(encrypted_sum)})
    input("按回车键进入下一步：结果解密...")


# --- Step 4: 结果揭晓 (解码逻辑) ---
def reveal_result():
    clean_screen()
    print("=== Step 4: 权威机构解密与公示 (Authority) ===")

    priv_data = load_json(PRIV_KEY_FILE)
    result_data = load_json(RESULT_FILE)
    config = load_json(CONFIG_FILE)

    if not priv_data or not result_data or not config: return

    candidates = config['candidates']
    slot_size = config['slot_size']

    # 重建含私钥的 Cipher
    cipher = PaillierCipher(generate_keys=False)
    cipher.n = priv_data['n']
    cipher.n_sq = cipher.n ** 2
    cipher.lam = priv_data['lam']
    cipher.mu = priv_data['mu']

    print("正在解密聚合密文...")
    decrypted_total = cipher.decrypt(int(result_data['encrypted_sum']))

    print(f"解密后的原始总数 (Encoded Integer): {decrypted_total}")
    print("-" * 50)
    print("正在解码选票分布...")

    # === 核心：结果解码逻辑 ===
    print(f"\n{'候选人':<10} | {'得票数':<10} | {'可视化'}")
    print("-" * 40)

    current_val = decrypted_total
    total_votes_check = 0

    for name in candidates:
        # 取余数得到当前位的票数
        count = current_val % slot_size
        # 地板除，移位到下一个候选人
        current_val = current_val // slot_size

        total_votes_check += count
        bar = "█" * count  # 简单的 ascii 柱状图
        print(f"{name:<10} | {count:<10} | {bar}")

    print("-" * 40)
    print(f"总有效票数: {total_votes_check}")

    # 验证是否溢出
    if current_val > 0:
        print("\n[警告] 检测到异常数据残留，可能发生了选票溢出攻击！")
    else:
        print("\n[验证] 数据完整性校验通过。")

    input("\n按回车键清理数据并退出...")
    # 清理文件
    for f in [PUB_KEY_FILE, PRIV_KEY_FILE, BALLOT_BOX_FILE, RESULT_FILE, CONFIG_FILE]:
        if os.path.exists(f): os.remove(f)


if __name__ == "__main__":
    while True:
        clean_screen()
        print("Paillier 多候选人隐私投票系统 v2.0")
        print("==================================")
        print("0. [Step 0] 配置候选人 (Admin)")
        print("1. [Step 1] 初始化密钥 (Authority)")
        print("2. [Step 2] 选民投票 (Client)")
        print("3. [Step 3] 云端计票 (Cloud Server)")
        print("4. [Step 4] 结果解密 (Authority)")
        print("x. 退出程序")

        c = input("\n请选择步骤: ")
        if c == '0':
            configure_election()
        elif c == '1':
            setup_election()
        elif c == '2':
            voter_action()
        elif c == '3':
            cloud_server_tally()
        elif c == '4':
            reveal_result()
        elif c.lower() == 'x':
            break