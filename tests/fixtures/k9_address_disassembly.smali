.class public final Lcom/fsck/k9/mail/Address;
.super Ljava/lang/Object;
.implements Ljava/io/Serializable;
.field public static final ATOM:Ljava/util/regex/Pattern;
.field public static final EMPTY_ADDRESS_ARRAY:[Lcom/fsck/k9/mail/Address;
.field public final address:Ljava/lang/String;
.field public final personal:Ljava/lang/String;
.method static constructor <clinit>()V
  .registers 1
  [Block #0]
    0000: const-string v0, "^(?:[a-zA-Z0-9!#$%&'*+\-/=?^_`{|}~]|\s)+$"
    0002: invoke-static v0, compile
    0005: move-result-object v0
    0006: invoke-virtual v0, getClass
    0009: sput-object v0, ATOM
    000b: const-4 v0, #0
    000c: new-array v0, v0, [Lcom/fsck/k9/mail/Address;
    000e: sput-object v0, EMPTY_ADDRESS_ARRAY
    0010: return-void
.method public synthetic constructor <init>(ILjava/lang/String;Ljava/lang/String;)V
  .registers 4
  [Block #0]
    0000: and-int-lit8 p1, p1, #2
    0002: if-eqz p1, # 0005
  [Block #1]
    0004: const-4 p3, #0
  [Block #2]
    0005: const-4 p1, #1
    0006: invoke-direct p0, p2, p3, p1, <init>
    0009: return-void
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Z)V
  .registers 6
  [Block #0]
    0000: invoke-virtual p1, getClass
    0003: invoke-direct p0, <init>
    0006: iput-object p1, p0, address
    0008: iput-object p2, p0, personal
    000a: if-eqz p3, # 0040
  [Block #1]
    000c: invoke-static p1, tokenize
    000f: move-result-object p3
    0010: invoke-virtual p3, getClass
    0013: array-length v0, p3
    0014: const-4 v1, #0
    0015: if-nez v0, # 0022
  [Block #2]
    0017: const-4 p0, #1
    0018: new-array p0, p0, [Ljava/lang/Object;
    001a: aput-object p1, p0, v1
    001c: const-string p1, "Invalid address: %s"
    001e: invoke-static p1, p0, e
    0021: return-void
  [Block #3]
    0022: aget-object p1, p3, v1
    0024: iget-object p3, p1, mAddress
    0026: iput-object p3, p0, address
    0028: iget-object p1, p1, mName
    002a: if-eqz p1, # 0032
  [Block #4]
    002c: invoke-virtual p1, length
    002f: move-result p3
    0030: if-nez p3, # 003e
  [Block #5]
    0032: if-eqz p2, # 003d
  [Block #6]
    0034: invoke-static p2, trim
    0037: move-result-object p1
    0038: invoke-virtual p1, toString
    003b: move-result-object p1
    003c: goto # 003e
  [Block #7]
    003d: const-4 p1, #0
  [Block #8]
    003e: iput-object p1, p0, personal
  [Block #9]
    0040: return-void
.method public final equals(Ljava/lang/Object;)Z
  .registers 6
  [Block #0]
    0000: const-4 v0, #1
    0001: if-ne p0, p1, # 0004
  [Block #1]
    0003: return v0
  [Block #2]
    0004: if-eqz p1, # 000b
  [Block #3]
    0006: invoke-virtual p1, getClass
    0009: move-result-object v1
    000a: goto # 000c
  [Block #4]
    000b: const-4 v1, #0
  [Block #5]
    000c: const-class v2, Lcom/fsck/k9/mail/Address;
    000e: invoke-virtual v2, v1, equals
    0011: move-result v1
    0012: const-4 v2, #0
    0013: if-nez v1, # 0016
  [Block #6]
    0015: return v2
  [Block #7]
    0016: invoke-virtual p1, getClass
    0019: check-cast p1, Lcom/fsck/k9/mail/Address;
    001b: iget-object v1, p0, address
    001d: iget-object v3, p1, address
    001f: invoke-static v1, v3, areEqual
    0022: move-result v1
    0023: if-nez v1, # 0026
  [Block #8]
    0025: return v2
  [Block #9]
    0026: iget-object p0, p0, personal
    0028: iget-object p1, p1, personal
    002a: invoke-static p0, p1, areEqual
    002d: move-result p0
    002e: if-nez p0, # 0031
  [Block #10]
    0030: return v2
  [Block #11]
    0031: return v0
.method public final getHostname()Ljava/lang/String;
  .registers 3
  [Block #0]
    0000: const-string v0, "@"
    0002: const-4 v1, #6
    0003: iget-object p0, p0, address
    0005: invoke-static v1, p0, v0, lastIndexOf$default
    0008: move-result v0
    0009: const-4 v1, #-1
    000a: if-ne v0, v1, # 000e
  [Block #1]
    000c: const-4 p0, #0
    000d: return-object p0
  [Block #2]
    000e: add-int-lit8 v0, v0, #1
    0010: invoke-virtual p0, v0, substring
    0013: move-result-object p0
    0014: return-object p0
.method public final hashCode()I
  .registers 2
  [Block #0]
    0000: iget-object v0, p0, address
    0002: invoke-virtual v0, hashCode
    0005: move-result v0
    0006: mul-int-lit8 v0, v0, #31
    0008: iget-object p0, p0, personal
    000a: if-eqz p0, # 0011
  [Block #1]
    000c: invoke-virtual p0, hashCode
    000f: move-result p0
    0010: goto # 0012
  [Block #2]
    0011: const-4 p0, #0
  [Block #3]
    0012: add-int-2addr v0, p0
    0013: return v0
.method public final toEncodedString()Ljava/lang/String;
  .registers 12
  [Block #0]
    0000: iget-object v0, p0, address
    0002: iget-object p0, p0, personal
    0004: if-eqz p0, # 0101
  [Block #1]
    0006: invoke-static p0, isBlank
    0009: move-result v1
    000a: if-eqz v1, # 000e
  [Block #2]
    000c: goto-16 # 0101
  [Block #3]
    000e: sget-object v1, BASE64_TABLE
    0010: invoke-virtual p0, length
    0013: move-result v1
    0014: const-4 v2, #0
    0015: move v3, v2
    0016: move v4, v3
  [Block #4]
    0017: const-4 v5, #1
    0018: if-ge v3, v1, # 0033
  [Block #5]
    001a: invoke-virtual p0, v3, charAt
    001d: move-result v6
    001e: sget-object v7, ATEXT_CHARS
    0020: invoke-virtual v7, v6, get
    0023: move-result v7
    0024: if-eqz v7, # 0028
  [Block #6]
    0026: move v4, v5
    0027: goto # 0030
  [Block #7]
    0028: invoke-static v6, isWhitespace
    002b: move-result v6
    002c: if-nez v6, # 0030
  [Block #8]
    002e: move v4, v2
    002f: goto # 0033
  [Block #9]
    0030: add-int-lit8 v3, v3, #1
    0032: goto # 0017
  [Block #10]
    0033: if-eqz v4, # 0037
  [Block #11]
    0035: goto-16 # 00f8
  [Block #12]
    0037: move v1, v2
    0038: move v3, v1
  [Block #13]
    0039: invoke-virtual p0, length
    003c: move-result v4
    003d: if-ge v1, v4, # 00d9
  [Block #14]
    003f: invoke-virtual p0, v1, charAt
    0042: move-result v4
    0043: const-16 v6, #9
    0045: if-eq v4, v6, # 00d4
  [Block #15]
    0047: const-16 v6, #32
    0049: if-ne v4, v6, # 004d
  [Block #16]
    004b: goto-16 # 00d4
  [Block #17]
    004d: add-int-2addr v3, v5
    004e: const-16 v7, #77
    0050: const-16 v8, #127
    0052: if-le v3, v7, # 0055
  [Block #18]
    0054: goto # 0059
  [Block #19]
    0055: if-lt v4, v6, # 0059
  [Block #20]
    0057: if-lt v4, v8, # 00d5
  [Block #21]
    0059: invoke-virtual p0, length
    005c: move-result v1
    005d: move v3, v2
  [Block #22]
    005e: const-16 v4, #255
    0060: if-ge v3, v1, # 0071
  [Block #23]
    0062: invoke-virtual p0, v3, charAt
    0065: move-result v7
    0066: if-le v7, v4, # 006b
  [Block #24]
    0068: sget-object v1, UTF_8
    006a: goto # 0078
  [Block #25]
    006b: if-le v7, v8, # 006e
  [Block #26]
    006d: move v5, v2
  [Block #27]
    006e: add-int-lit8 v3, v3, #1
    0070: goto # 005e
  [Block #28]
    0071: if-eqz v5, # 0076
  [Block #29]
    0073: sget-object v1, US_ASCII
    0075: goto # 0078
  [Block #30]
    0076: sget-object v1, ISO_8859_1
  [Block #31]
    0078: invoke-static p0, v1, encode
    007b: move-result-object v3
    007c: array-length v5, v3
    007d: const-string v7, "=?"
    007f: if-nez v5, # 0082
  [Block #32]
    0081: goto # 00ba
  [Block #33]
    0082: sget-object v5, Q_RESTRICTED_CHARS
    0084: array-length v8, v3
    0085: move v9, v2
  [Block #34]
    0086: if-ge v2, v8, # 0098
  [Block #35]
    0088: aget-byte v10, v3, v2
    008a: and-int-2addr v10, v4
    008b: if-eq v10, v6, # 0095
  [Block #36]
    008d: invoke-virtual v5, v10, get
    0090: move-result v10
    0091: if-nez v10, # 0095
  [Block #37]
    0093: add-int-lit8 v9, v9, #1
  [Block #38]
    0095: add-int-lit8 v2, v2, #1
    0097: goto # 0086
  [Block #39]
    0098: mul-int-lit8 v9, v9, #100
    009a: array-length v2, v3
    009b: div-int-2addr v9, v2
    009c: const-16 v2, #30
    009e: if-le v9, v2, # 00ba
  [Block #40]
    00a0: new-instance v2, Ljava/lang/StringBuilder;
    00a2: invoke-direct v2, v7, <init>
    00a5: invoke-virtual v1, name
    00a8: move-result-object v4
    00a9: invoke-virtual v2, v4, append
    00ac: const-string v4, "?B?"
    00ae: invoke-virtual v2, v4, append
    00b1: invoke-virtual v2, toString
    00b4: move-result-object v2
    00b5: invoke-static v2, p0, v1, v3, encodeB
    00b8: move-result-object p0
    00b9: goto # 00f8
  [Block #41]
    00ba: new-instance v2, Ljava/lang/StringBuilder;
    00bc: invoke-direct v2, v7, <init>
    00bf: invoke-virtual v1, name
    00c2: move-result-object v4
    00c3: invoke-virtual v2, v4, append
    00c6: const-string v4, "?Q?"
    00c8: invoke-virtual v2, v4, append
    00cb: invoke-virtual v2, toString
    00ce: move-result-object v2
    00cf: invoke-static v2, p0, v1, v3, encodeQ
    00d2: move-result-object p0
    00d3: goto # 00f8
  [Block #42]
    00d4: move v3, v2
  [Block #43]
    00d5: add-int-lit8 v1, v1, #1
    00d7: goto-16 # 0039
  [Block #44]
    00d9: new-instance v1, Ljava/lang/StringBuilder;
    00db: const-string v2, """
    00dd: invoke-direct v1, v2, <init>
    00e0: sget-object v2, QUOTE
    00e2: invoke-virtual v2, p0, matcher
    00e5: move-result-object p0
    00e6: const-string v2, "\\$0"
    00e8: invoke-virtual p0, v2, replaceAll
    00eb: move-result-object p0
    00ec: invoke-virtual v1, p0, append
    00ef: const-16 p0, #34
    00f1: invoke-virtual v1, p0, append
    00f4: invoke-virtual v1, toString
    00f7: move-result-object p0
  [Block #45]
    00f8: const-string v1, " <"
    00fa: const-string v2, ">"
    00fc: invoke-static p0, v1, v0, v2, m
    00ff: move-result-object p0
    0100: return-object p0
  [Block #46]
    0101: return-object v0
.method public final toString()Ljava/lang/String;
  .registers 4
  [Block #0]
    0000: iget-object v0, p0, address
    0002: iget-object p0, p0, personal
    0004: if-eqz p0, # 0041
  [Block #1]
    0006: invoke-static p0, isBlank
    0009: move-result v1
    000a: if-eqz v1, # 000d
  [Block #2]
    000c: goto # 0041
  [Block #3]
    000d: if-eqz p0, # 0037
  [Block #4]
    000f: sget-object v1, ATOM
    0011: invoke-virtual v1, p0, matcher
    0014: move-result-object v1
    0015: invoke-virtual v1, matches
    0018: move-result v1
    0019: if-eqz v1, # 001c
  [Block #5]
    001b: goto # 0038
  [Block #6]
    001c: const-string v1, "^".*"$"
    001e: invoke-static v1, compile
    0021: move-result-object v1
    0022: invoke-virtual v1, getClass
    0025: invoke-virtual v1, p0, matcher
    0028: move-result-object v1
    0029: invoke-virtual v1, matches
    002c: move-result v1
    002d: if-eqz v1, # 0030
  [Block #7]
    002f: goto # 0038
  [Block #8]
    0030: const-string v1, """
    0032: invoke-static v1, p0, v1, m
    0035: move-result-object p0
    0036: goto # 0038
  [Block #9]
    0037: const-4 p0, #0
  [Block #10]
    0038: const-string v1, " <"
    003a: const-string v2, ">"
    003c: invoke-static p0, v1, v0, v2, m
    003f: move-result-object p0
    0040: return-object p0
  [Block #11]
    0041: return-object v0
