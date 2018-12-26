# ssh 协议分析
## 1. 协议版本交换 (RFC 4253 4.2节)
当tcp连接建立之后，双方交换版本信息(identification string)。
格式为： SSH-protoversion-softwareversion SP comments CR LF
(SP为ascii码空格，CR为ascii码回车，LF为ascii码换行)
>  __RFC 4253 4.2.  Protocol Version Exchange__ 
> 
> When the connection has been established, both sides MUST send an  identification string.  This identification string MUST be
>
> SSH-protoversion-softwareversion SP comments CR LF

交换完版本信息之后立刻进行Key exchange
> __RFC 4253 4.2.__
> ...
> Key exchange will begin immediately after sending this identifier. All packets following the identification string SHALL use the binary packet  protocol, which is described in Section 6.

## 2. Key exchange 
### 2.1. Binary Packet Protocol （RFC 4253 6. 节）
Key exchange阶段的每个包都用以下格式发送：
>      uint32    packet_length (包的长度，以字节计数，除去packet_length本身和mac)
>      byte      padding_length(random padding字段的长度)
>      byte[n1]  payload; n1 = packet_length - padding_length - 1 (包的内容)
>      byte[n2]  random padding; n2 = padding_length (随机的填充字段)
>      byte[m]   mac (Message Authentication Code - MAC); m = mac_length

### 2.2. 算法协商 / Key exchange init (RFC 4253 7.1.节）
双方发送如下格式的包（一下内容都在2.1节的payload中）：
>      byte         SSH_MSG_KEXINIT
>      byte[16]     cookie (random bytes)
>      name-list    kex_algorithms
>      name-list    server_host_key_algorithms
>      name-list    encryption_algorithms_client_to_server
>      name-list    encryption_algorithms_server_to_client
>      name-list    mac_algorithms_client_to_server
>      name-list    mac_algorithms_server_to_client
>      name-list    compression_algorithms_client_to_server
>      name-list    compression_algorithms_server_to_client
>      name-list    languages_client_to_server
>      name-list    languages_server_to_client
>     boolean      first_kex_packet_follows
>      uint32       0 (reserved for future extension)

### 2.3. run key exchange
> 当算法协商完成之后，紧接着开始具体的密钥交换算法，这里以Diffie-Hellan算法为例（通常）

[dh算法的基本步骤(链接)](https://security.stackexchange.com/questions/45963/diffie-hellman-key-exchange-in-plain-english)

__Client:__ 
Message Code： Diffie-Hellman Group Exchange Request(34)
DH GEX Min： 1024
DH GEX Number of Bits:4096
DH GEX Max: 8192
(对于密钥的约束)
__Server：__
Message Code： Diffie-Hellman Group Exchange Group(31)
Multi Precision Integer Length: 513
DH GEX modulus(P): ...
Multi Precision Integer Length: 1
DH GEX base (G): 05
(Server 创建两个公开的素数 P和G)
__Client：__
Message Code:Diffie-Hellman Group Exchange Init(32)
Multi Precision Integer Length: 512
DH client e:...
(client 用一个私密的数x，计算出 e=G^x mod P)
__Server:__
Message Code：Diffie-hellman Group Exchange Reply(33)
Host Key length: 279
Host Key type:ssh-rsa
Multi Precision Integer Length :3
RSA public exponent (e):010001
Multi Precision Integer Length: 257
RSA modulus (N):...
Muti Precision Interger Length: 513
DH Server f:...
KEX H signature legnth:271
KEX H signature: ...
(
- 在这一步中server首先给出自己的rsa公钥用于服务器认证。
- 接着给出f，f的计算方法和e类似，不过是server用一个私密的数y，计算出f=G^y mod P。可以证明 e^y mod P == f^x mod P, 所以Client和Server可以生成同一个秘密的共享密钥 K.
- KEX H signature 是Server同rsa私钥对exchange Hash进行签名之后的结果，用于client对server的认证。
)

### 2.4. New Keys
__Server__:
Message Code: New Keys (21)
__Client__:
Message Code: New Keys (21)
(New Keys之后的所有消息都用以上的Key进行加密)
























