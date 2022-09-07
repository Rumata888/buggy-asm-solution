FROM gcc:10.3.0 as builder
RUN apt update && apt install git
WORKDIR /lib_build/
RUN git clone https://github.com/Rumata888/aztec-2
WORKDIR /lib_build/aztec-2/barretenberg
COPY ./task.patch  /lib_build/aztec-2/barretenberg
COPY ./builder.sh  /lib_build/aztec-2/barretenberg
COPY ./malicious_lib.cpp /lib_build/aztec-2/barretenberg/
RUN chmod +x builder.sh && ./builder.sh

FROM python:3.9-slim
RUN apt update && apt install -y libstdc++6 sagemath
RUN groupadd -r crypto && useradd -r -u 1001 -g crypto crypto

RUN mkdir -p /home/crypto
RUN chown -R crypto /home/crypto
USER crypto

RUN sage --python -m pip install --user pycryptodome z3-solver scapy
COPY mal_dh_support.py /home/crypto
COPY mal_client.py /home/crypto
COPY extra_flag_solver.py /home/crypto
COPY task_interaction.pcapng /home/crypto
COPY --from=builder /lib_build/aztec-2/barretenberg/mallibdh.so /home/crypto
COPY --from=builder /lib_build/aztec-2/barretenberg/src/aztec/ecc/fields/asm_macros.hpp /home/crypto/
WORKDIR /home/crypto

CMD ["sage","/home/crypto/mal_client.py", "slow","cryptotraining.zone", "1353"]