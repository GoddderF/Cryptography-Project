import json
import os
import sys
from paillier_core import PaillierCipher

# 模拟的文件名，代表网络传输的数据包
PUB_KEY_FILE = "network_public_key.json"
PRIV_KEY_FILE = "offline_private_key.json"
BALLOT_BOX_FILE = "network_ballot_box.json"
RESULT_FILE = "network_encrypted_result.json"


def clean_screen():
    # 简单的清屏，让演示更像个系统
    os.system('cls' if os.name == 'nt' else 'clear')


def save_json(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"  [传输] 数据已写入 {filename}")


def load_json(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"错误：找不到文件 {filename}，请先运行上一步骤。")
        sys.exit(1)


# --- 角色 1: 权威机构 (初始化) ---
def setup_election():
    clean_screen()
    print("=== 角色 1: 权威机构 (Trusted Authority) ===")
    print("正在初始化选举系统密钥...")

    # 实例化并生成密钥
    cipher = PaillierCipher(key_size=128)  # 演示可以用大一点的 key

    # 序列化公钥 (n, g)
    pub_data = {"n": cipher.n, "g": cipher.g}
    save_json(PUB_KEY_FILE, pub_data)

    # 序列化私钥 (lambda, mu) - 注意：这个文件应该被严密保护
    priv_data = {"lam": cipher.lam, "mu": cipher.mu, "n": cipher.n}
    save_json(PRIV_KEY_FILE, priv_data)

    # 初始化空的投票箱
    save_json(BALLOT_BOX_FILE, [])

    print("\n[系统状态] 选举已开始！公钥已发布到网络，私钥已离线存储。")
    input("\n按回车键进入下一步：选民投票...")


# --- 角色 2: 选民 (客户端) ---
def voter_action():
    clean_screen()
    print("=== 角色 2: 选民客户端 (Voter Client) ===")
    print("正在从网络获取公钥...")
    print("1")
    pub_data = load_json(PUB_KEY_FILE)
    print("1")

    # 临时重建一个只有公钥的 Cipher 对象
    # 这里我们hack一下，只用 n 和 g，不需要私钥
    cipher = PaillierCipher(generate_keys=False)
    cipher.n = pub_data['n']
    cipher.g = pub_data['g']
    cipher.n_sq = cipher.n ** 2

    print("-" * 40)
    print("候选人名单: ")
    print("  1. Alice (输入 1)")
    print("  0. Bob   (输入 0)")
    print("-" * 40)

    ballots = load_json(BALLOT_BOX_FILE)

    while True:
        choice = input("请输入你的选择 (1/0)，输入 'q' 结束投票: ")
        if choice.lower() == 'q':
            break
        if choice not in ['0', '1']:
            print("无效输入，请重试。")
            continue

        val = int(choice)

        # 加密
        print(f"正在加密选票 [{val}] ...")
        c = cipher.encrypt(val)

        # 将大整数转为字符串存储，模拟发包
        ballots.append(str(c))
        print(f"  -> 密文生成: {str(c)[:10]}... (已发送至云端)")

    save_json(BALLOT_BOX_FILE, ballots)
    print(f"\n[系统状态] 所有选票已加密上传。当前票箱共 {len(ballots)} 张票。")
    input("\n按回车键进入下一步：云端计票...")


# --- 角色 3: 云端服务器 (不掌握私钥) ---
def cloud_server_tally():
    clean_screen()
    print("=== 角色 3: 云端计票服务器 (Untrusted Cloud) ===")
    print("警告：本服务器没有私钥，无法查看具体选票内容。")
    print("正在执行同态运算...")

    pub_data = load_json(PUB_KEY_FILE)
    ballots = load_json(BALLOT_BOX_FILE)

    if not ballots:
        print("票箱为空！")
        return

    # 重建只有公钥的 Cipher
    cipher = PaillierCipher(generate_keys=False)
    cipher.n = pub_data['n']
    cipher.n_sq = cipher.n ** 2

    # 开始同态加法 (密文乘积)
    # 初始值设为加密的 0，或者直接取第一个密文
    # 为了严谨，我们取第一个，然后累乘后面的
    encrypted_sum = int(ballots[0])

    print(f"正在处理第 1/{len(ballots)} 张选票...")

    for i in range(1, len(ballots)):
        c_next = int(ballots[i])
        encrypted_sum = cipher.homomorphic_add(encrypted_sum, c_next)
        print(f"正在处理第 {i + 1}/{len(ballots)} 张选票... (同态聚合中)")

    print("\n计算完成！")
    print(f"聚合后的密文结果: {str(encrypted_sum)[:20]}...")

    save_json(RESULT_FILE, {"encrypted_sum": str(encrypted_sum)})
    input("\n按回车键进入下一步：公布结果...")


# --- 角色 1 (回归): 权威机构解密 ---
def reveal_result():
    clean_screen()
    print("=== 角色 1: 权威机构 (Trusted Authority) ===")
    print("收到云端计算结果，正在取出私钥进行解密...")

    priv_data = load_json(PRIV_KEY_FILE)
    result_data = load_json(RESULT_FILE)

    # 重建拥有私钥的 Cipher
    cipher = PaillierCipher(generate_keys=False)
    cipher.n = priv_data['n']
    cipher.n_sq = cipher.n ** 2
    cipher.lam = priv_data['lam']
    cipher.mu = priv_data['mu']

    c_sum = int(result_data['encrypted_sum'])

    # 解密
    total_votes = cipher.decrypt(c_sum)

    ballots = load_json(BALLOT_BOX_FILE)
    total_voters = len(ballots)

    print("\n" + "=" * 40)
    print("      选举最终结果      ")
    print("=" * 40)
    print(f"总参与人数: {total_voters}")
    print("-" * 40)
    print(f"Alice (1) 得票数: {total_votes}")
    print(f"Bob (0)   得票数: {total_voters - total_votes}")
    print("=" * 40)

    # 清理临时文件
    input("\n演示结束。按回车清理临时文件并退出。")
    for f in [PUB_KEY_FILE, PRIV_KEY_FILE, BALLOT_BOX_FILE, RESULT_FILE]:
        if os.path.exists(f):
            os.remove(f)
    print("清理完毕。")


if __name__ == "__main__":
    # 简单的菜单驱动
    while True:
        clean_screen()
        print("Paillier 同态加密投票系统 - 全流程演示")
        print("1. [Step 1] 初始化密钥 (Authority)")
        print("2. [Step 2] 选民投票 (Client)")
        print("3. [Step 3] 云端计票 (Cloud Server)")
        print("4. [Step 4] 结果解密 (Authority)")
        print("0. 退出")

        choice = input("\n请按顺序选择步骤: ")

        if choice == '1':
            setup_election()
        elif choice == '2':
            voter_action()
        elif choice == '3':
            cloud_server_tally()
        elif choice == '4':
            reveal_result()
        elif choice == '0':
            break