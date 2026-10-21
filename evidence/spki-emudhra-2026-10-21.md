# eMudhra 事件 · SPKI SHA-256 检测锚点

来源（一手）：https://www.openwall.com/lists/oss-security/2026/10/20/1
抓取/核对：2026-10-21，漏洞侦察 从 oss-security 原文抄录；本表为原文逐条誊录，未改动哈希。

## 3 个根

| 根 | SPKI SHA-256 |
|---|---|
| AAA Certificate Services | `bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3` |
| emSign Root TLS CA - G3 | `c619e4780ed8e0abeda24ad732567de4383a7ea941338f6d1a7d1b49ac792fe9` |
| emSign ECC Root CA - G3 | `8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782` |

## 8 张中间 CA（6 TLS + 2 代码签名）

| 中间 CA | 用途 | SPKI SHA-256 |
|---|---|---|
| EM EV TLS CA - G3B | TLS | `e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a4` |
| EM OV TLS CA - G3B | TLS | `43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717` |
| EM DV TLS CA - G3B | TLS | `ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105` |
| EM EV TLS CA - G3C | TLS | `5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0` |
| EM OV TLS CA - G3C | TLS | `63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8` |
| EM DV TLS CA - G3C | TLS | `49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f` |
| EM OV CS CA - G3B | 代码签名 | `ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6` |
| EM OV CS CA - G3C | 代码签名 | `92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30` |

Sectigo 交叉签名 8 张：SPKI 与上表相同（CCADB A012333/354/347/334/343/342/352/350）→ **检测只认 SPKI，不必区分签发路径**。

## 用法

```bash
openssl s_client -connect host:443 -servername host </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256
# 输出与上表任一命中 = 链上出现受影响 CA
```

## 注意

- 根因是**弱密钥**（KGC 生成脚本缺陷：出现 1 字节私钥、连续整数 155/156 这类 P384 私钥），不是普通「私钥被窃」。
- CT 日志暂未见被签发的伪造证书记录，但厂商口径是「近期很可能被滥用」——**按已泄露处置，不按「尚未发生」处置**。
