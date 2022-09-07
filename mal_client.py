from struct import pack
from more_itertools import first
from mal_dh_support import *
from extra_flag_solver import find_buggy_values
import socket
import sys
import re
from random import randint
from sage.all import *
from scapy.all import *

# Modulus
P = 21888242871839275222246405745257275088696311157297823662689037894645226208583
# Field
f = GF(P)
# R used in Montgomery multiplication
R = f(1 << 256)
R_inv = R ** (-1)
# This is needed to solve equations
curve_ring = PolynomialRing(f, ["x"])


def bad_point_generator():
    """Generate bad points that produce points on other curves, when they are doubled"""

    # Load the malicious library that calculates erroneous points
    cryptor = Cryptor(os.urandom(32))
    # Initialize the generator that uses z3 to generate values that set the missed CF flag to 1
    buggy_val_generator = find_buggy_values("asm_macros.hpp")
    # Start the loop of finding values
    b_cache = []
    while True:
        # Get a value from the SMT generator
        buggy_value_montgormery_form = next(buggy_val_generator)
        print("Found solution for CF")
        buggy_value_plain_form = buggy_value_montgormery_form * R_inv
        # Another value that is squared is 3*(x^2)
        equation = 3 * (curve_ring.gen() ** 2) - f(buggy_value_plain_form)
        roots = equation.roots()
        if len(roots) > 0:
            print("Curve equation for 3*(x^2) case has roots")
            for (root, _) in roots:
                x = root
                y_sqr = f(x) ** 3 + 3
                if y_sqr.is_square():
                    y = y_sqr.sqrt()
                    (new_x, new_y) = cryptor.double_point(x, y)
                    new_b = -(f(new_x) ** 3 - f(new_y) ** 2)
                    if new_b not in b_cache:
                        print(
                            f"Discovered a solution with entry_point({hex(x)},{hex(y)}),"
                            f" intermediate_point({hex(new_x)},{(new_y)}), and b={hex(new_b)}",
                        )
                        yield (x, y, new_x, new_y, new_b)
                        b_cache.append(new_b)
                    else:
                        print("Discovered a point for a previously found curve")
                    # Try another root, too
                    old_b = new_b
                    y = P - y
                    (new_x, new_y) = cryptor.double_point(x, y)
                    new_b = -(f(new_x) ** 3 - f(new_y) ** 2)
                    if old_b == new_b:
                        print("Old root is the same as the new one")
                    else:
                        if new_b not in b_cache:
                            print(
                                f"Discovered a solution with entry_point({hex(x)},{hex(y)}),"
                                f" intermediate_point({hex(new_x)},{(new_y)}), and b={hex(new_b)}",
                            )
                            yield (x, y, new_x, new_y, new_b)
                            b_cache.append(new_b)
                        else:
                            print("Discovered a point for a previously found curve")

                else:
                    print("The root doesn't produce a quardatic residue for y^2")
        else:
            print("The curve equation for 3*(x^2) case has 0 solutions")

        # We can't trigger the bug with x^2 or y^2 since this will break the curve check
        # One option is to trigger the bug during y^4
        # This can only work if the value is a square
        if buggy_value_plain_form.is_square():
            print("It is a quadratic residue")
            # y^2=buggy value
            precursor = buggy_value_plain_form.sqrt()
            # We need to solve the equation (x^3+3-buggy_value_plain_form) for x (it might not always have roots)
            equation = curve_ring.gen() ** 3 + 3 - buggy_value_plain_form
            roots = equation.roots()
            if len(roots) > 0:
                print("Curve equation for y^2 case has roots")
                for (root, _) in roots:
                    x = root
                    y = precursor
                    (new_x, new_y) = cryptor.double_point(x, y)
                    new_b = -(f(new_x) ** 3 - f(new_y) ** 2)
                    if new_b not in b_cache:
                        print(
                            f"Discovered a solution with entry_point({hex(x)},{hex(y)}),"
                            f" intermediate_point({hex(new_x)},{(new_y)}), and b={hex(new_b)}",
                        )
                        yield (x, y, new_x, new_y, new_b)
                        b_cache.append(new_b)
                    else:
                        print("Discovered a point for a previously found curve")
                    # Because of coarse reductions, we can sometimes land on a different value, so it is important to try both roots
                    old_b = new_b
                    y = P - y
                    (new_x, new_y) = cryptor.double_point(x, y)
                    new_b = -(f(new_x) ** 3 - f(new_y) ** 2)
                    if old_b == new_b:
                        print("The other root is the same")
                    else:
                        if new_b not in b_cache:
                            print(
                                f"Discovered a solution with entry_point({hex(x)},{hex(y)}),"
                                f" intermediate_point({hex(new_x)},{(new_y)}), and b={hex(new_b)}",
                            )
                            yield (x, y, new_x, new_y, new_b)
                            b_cache.append(new_b)
                        else:
                            print("Discovered a point for a previously found curve")

            else:
                print("The curve equation has 0 solutions")
        else:
            print("It is not a quadratic residue")
        # Another value that is squared is x+y^2. So we have a system of equations:
        # x+y^2 = buggy_value
        # y^2=x^3+3
        # buggy_value - x = x^3 + 3
        # x^3 + x + (3 - buggy_value) = 0
        equation = (
            curve_ring.gen() ** 3 + curve_ring.gen() + f(3) - f(buggy_value_plain_form)
        )
        roots = equation.roots()
        if len(roots) > 0:
            print("Curve equation for y^2 + x case has roots")
            for (root, _) in roots:
                x = root
                y_sqr = f(buggy_value_plain_form) - x
                if y_sqr.is_square():
                    y = y_sqr.sqrt()
                    (new_x, new_y) = cryptor.double_point(x, y)
                    new_b = -(f(new_x) ** 3 - f(new_y) ** 2)
                    if new_b not in b_cache:
                        print(
                            f"Discovered a solution with entry_point({hex(x)},{hex(y)}),"
                            f" intermediate_point({hex(new_x)},{(new_y)}), and b={hex(new_b)}",
                        )
                        yield (x, y, new_x, new_y, new_b)
                        b_cache.append(new_b)
                    else:
                        print("Discovered a point for a previously found curve")
                    # Try another root, too
                    old_b = new_b
                    y = P - y
                    (new_x, new_y) = cryptor.double_point(x, y)
                    new_b = -(f(new_x) ** 3 - f(new_y) ** 2)
                    if old_b == new_b:
                        print("Old root is the same as the new one")
                    else:
                        if new_b not in b_cache:
                            print(
                                f"Discovered a solution with entry_point({hex(x)},{hex(y)}),"
                                f" intermediate_point({hex(new_x)},{(new_y)}), and b={hex(new_b)}",
                            )
                            yield (x, y, new_x, new_y, new_b)
                            b_cache.append(new_b)
                        else:
                            print("Discovered a point for a previously found curve")

                else:
                    print("The root doesn't produce a quardatic residue for y^2")
        else:
            print("The curve equation for y^2 + x case has 0 solutions")


def collect_points_for_breaking(use_fast):
    point_generator = bad_point_generator()
    found_orders = []
    found_bs = []
    params = []
    if use_fast:
        print("Using precomputed points for the attack")
        params = [
            (
                17517444236489252494615922836759668006934743537213361734361888955506228343030,
                5137264766849869327700504465912302239395326190749115638250366510729766838498,
                18683520338743464965248706396927227290134166393102152313400994450160921444137,
                13943658211472488293255528493233873331498165607717442435562989367125501613593,
                11691085842352433436899206298254262603980847210186066544613618578417400694598,
            ),
            (
                18589042494071855899844201028157863791058471274317162187017119597353009025035,
                5099562921663048898147591615544831988295224485818231131260967210831738038784,
                10245326890959392994853887625075202381455845293868672976935524564900614806427,
                200310812597815923844530029149971771067243201672934230326117584709030656620,
                5196581007159640451207582435903918840427400540043699374666900191308945641464,
            ),
            (
                1074421418757095662363129466044764622916522589156263948701913064573729119895,
                2213171119522821890198936701144301471441556775963163274943665364515109201778,
                7267632310563239917874443276770538857392586896761513313449811168458598480532,
                16365893086249309055079930756365493970981083794432968847495184752795668765223,
                16849514243152351713002776542120321576652450277514471039227786427575665532179,
            ),
            (
                13083239606310631026876432997857961027662507529509848212582337054063057697954,
                7172210780505730833055373019576051113616705644480121061987366280157962258247,
                8927162687565668068260564170012174450665884573601031175482649882788948948101,
                11517109253475655712896816592908156040779655425092014644628842881234834256386,
                18825169925124053072681684175818145971161462502601087434324372194286702847216,
            ),
            (
                21254508489953815479157027039030953856487930554109698835118944122258408572213,
                10557011555273394904835774752073158244728155223423147727266593355131100985422,
                19422345473296885322838940672035701637089117518216271015581459897639532403401,
                14360909628924828155069933173694805255223792735887715061643677360054268889134,
                9404599178901095428241756440792575389667133208078907092985348198330829508816,
            ),
        ]
    else:
        print("Computing points from scratch")
    if len(params) != 0:
        return params
    factor_dict = {}
    while True:
        (x, y, new_x, new_y, new_b) = next(point_generator)
        e = EllipticCurve(f, [0, new_b])
        eorder = e.order()
        if eorder in found_orders:
            print("New b, but order has been already found")
            continue
        found_orders.append(eorder)
        current_factors = eorder.factor()
        # print(current_factors)
        updated = False
        for (factor, power) in current_factors:
            factor = int(factor)
            power = int(power)
            # print(factor, power)
            if factor < (1 << 32) and (
                factor not in factor_dict or factor_dict[factor] < power
            ):
                factor_dict[factor] = power
                updated = True
        if updated:
            params.append((x, y, new_x, new_y, new_b))
            current_reconstructed_scalar = 1
            for key in factor_dict.keys():
                current_reconstructed_scalar *= key ** factor_dict[key]
            print("Discovered new factors")
            print(
                f"Currently CRT produces {len(bin(current_reconstructed_scalar))-2} out of 372 desired bits"
            )
            if current_reconstructed_scalar > (1 << 372):
                # We need some leeway
                break
    # print(params)
    print("Finished finding points. Collected enough.")
    return params


def pseudo_random_function_generator(limit, modulus):
    a = randint(1, modulus - 1)
    b = randint(1, modulus - 1)
    c = randint(1, modulus - 1)

    def random_func(point):
        try:
            x = int(point.xy()[0])
        except ZeroDivisionError:
            x = int(c)

        return 1 + ((a * x + b) % modulus) % (limit - 1)

    return random_func


def pollard(start, gen, exp, group_order):
    if group_order < 512:
        temp = start + gen
        i = 1
        for i in range(1, 512):
            if temp == exp:
                k = i % group_order

                print(k, group_order, k * gen, exp)
                return k
            temp += gen

    log = len(Integer(group_order).bits())
    limit = log >> 1
    while True:
        cur_rand = pseudo_random_function_generator(limit, group_order)
        xT = 1
        yT = start + gen
        while xT < group_order * 5:
            add = 1 << cur_rand(yT)
            xT += add
            yT = yT + (add * gen)
        xW = 0
        yW = exp
        while xW < xT:
            add = 1 << cur_rand(yW)
            xW += add
            yW = yW + (add * gen)
            if yW == yT:
                k = (xT - xW) % group_order
                print(k, k * gen, exp)
                print("Found")
                return k


def solve_for_two(gen_x, gen_y, exp_x, exp_y, b):
    """Solve dlog in subgroups"""
    ec = EllipticCurve(f, [0, b])
    ec_order = ec.order()
    factors = ec_order.factor()
    basic_gen = ec(gen_x, gen_y)
    basic_exp = ec(exp_x, exp_y)
    results = []
    pif = basic_gen * ec_order
    remainder_dict = {}
    for (factor, power) in factors:
        if factor >= (1 << 32):
            continue

        current_gen = basic_gen * (ec_order // factor)
        start = pif
        k = 0
        for i in range(power):
            if current_gen.is_zero():
                # print("Generator is zero", factor, i)
                break

            current_exp = basic_exp * (ec_order // (factor ** (i + 1)))

            current_shifter = basic_gen * (ec_order // (factor ** (i + 1)))
            start = current_shifter * k
            k_i = discrete_log(current_exp - start, current_gen, factor, operation="+")
            # k_i = pollard(start, current_gen, current_exp, factor)
            # print("Check:", k_i_1, k_i)
            k = k + k_i * (factor**i)
            print(f"Got some information. k = {k} mod {factor**(i+1)}")
            remainder_dict[factor] = (i + 1, k)
    return remainder_dict


def load_traffic():
    """Load the legitimate client-server traffic from pcap"""
    pcap_flow = rdpcap("task_interaction.pcapng")
    client_packets = []
    server_packets = []
    for packet in pcap_flow:
        if len(packet[TCP].payload) != 0:
            if packet[TCP].dport == 1337:
                client_packets.append(bytes(packet[TCP].payload))
            else:
                server_packets.append(bytes(packet[TCP].payload))
    print(client_packets)
    # Return the client public key, server public key and encrypted flag
    return (
        client_packets[1][4:],
        server_packets[1][4:],
        server_packets[-1][4:],
        client_packets[-1][4:],
    )


def run_client(mode, host, port):
    if mode == "fast":

        breaking_points = collect_points_for_breaking(True)
    elif mode == "slow":
        breaking_points = collect_points_for_breaking(False)
    else:
        print("Wrong mode")
        return
    port = int(port)
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.connect((host, port))
    client = MalClient(serverSocket)
    print("Connected to server:", client.confirmServer())
    print("Starting to collect points")
    all_remainders = {}
    for (breaking_x, breaking_y, intermediate_x, intermediate_y, b) in breaking_points:
        print("Testing point...")
        answer = client.testPoint(breaking_x, breaking_y)
        # print("Initial point:", hex(intermediate_x), hex(intermediate_y))
        # print(answer)
        (new_point_x, new_point_y) = tuple(
            map(
                f,
                [
                    int(x, 16)
                    for x in re.findall(
                        "{ (0x[0-9a-f]+), (0x[0-9a-f]+) }", answer.decode()
                    )[0]
                ],
            )
        )
        generator_x = f(intermediate_x)
        generator_y = f(intermediate_y)

        assert (f(intermediate_y) ** 2 - f(intermediate_x) ** 3) == (
            new_point_y**2 - new_point_x**3
        )
        # Solve dlog in subgroups
        print("Solving dlog in subgroups...")
        current_remainders = solve_for_two(
            intermediate_x, intermediate_y, new_point_x, new_point_y, b
        )
        for factor in current_remainders.keys():
            if (
                factor not in all_remainders
                or all_remainders[factor][0] < current_remainders[factor][0]
            ):
                all_remainders[factor] = current_remainders[factor]
    rems = []
    mods = []
    all_mod = 1
    for factor in all_remainders.keys():
        (power, remainder) = all_remainders[factor]
        rems.append(remainder)
        mods.append(factor**power)
        all_mod *= factor**power
    result = f(CRT(rems, mods))
    result *= f(2)
    print("Found server's secret key:", hex(result))

    (client_pubkey, server_pubkey, encrypted_flag, encrypted_password) = load_traffic()
    client = MalClient(0, private_key=long_to_bytes(int(result), 32)[::-1])
    print("Public keys equal: ", client.getPublicKey() == server_pubkey)
    print("Created fake server to decrypt")
    client.establishFakeTunnel(client_pubkey)

    print("Old message:", client.receiveFake(encrypted_flag)[1].decode())
    decrypted_password = client.receiveFake(encrypted_password)[1]
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.connect((host, port))
    client = MalClient(serverSocket)
    print("Connected to server")
    (result, message) = client.establishTunnel()
    if not result:
        print(f"Error establishing tunnel: {message.decode()}")
        return
    else:
        print("Established tunnel.")
    client.send(decrypted_password)
    print(f"Received from server: {client.receive()[1].decode()}")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} fast|slow <hostname> <port>")
        print(
            f'Use "{sys.argv[0]} slow <hostname> <port>" for full attack with symbolic execution search for points'
        )
        print(
            f'Use "{sys.argv[0]} fast <hostname> <port>" to quickly test with precomputed points'
        )
        exit()

    run_client(sys.argv[1], sys.argv[2], sys.argv[3])
