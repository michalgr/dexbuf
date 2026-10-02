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
    0002: invoke-static v0, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;
    0005: move-result-object v0
    0006: invoke-virtual v0, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    0009: sput-object v0, Lcom/fsck/k9/mail/Address;->ATOM:Ljava/util/regex/Pattern;
    000b: const-4 v0, #0
    000c: new-array v0, v0, [Lcom/fsck/k9/mail/Address;
    000e: sput-object v0, Lcom/fsck/k9/mail/Address;->EMPTY_ADDRESS_ARRAY:[Lcom/fsck/k9/mail/Address;
    0010: return-void
.method public synthetic constructor <init>(ILjava/lang/String;Ljava/lang/String;)V
  .registers 4
  [Block #0]
    ; succs: #1, #2
    0000: and-int-lit8 p1, p1, #2
    0002: if-eqz p1, # 0005
  [Block #1]
    ; preds: #0
    ; succs: #2
    0004: const-4 p3, #0
  [Block #2]
    ; preds: #0, #1
    0005: const-4 p1, #1
    0006: invoke-direct p0, p2, p3, p1, Lcom/fsck/k9/mail/Address;-><init>(Ljava/lang/String;Ljava/lang/String;Z)V
    0009: return-void
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Z)V
  .registers 6
  [Block #0]
    ; succs: #1, #9
    0000: invoke-virtual p1, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    0003: invoke-direct p0, Ljava/lang/Object;-><init>()V
    0006: iput-object p1, p0, Lcom/fsck/k9/mail/Address;->address:Ljava/lang/String;
    0008: iput-object p2, p0, Lcom/fsck/k9/mail/Address;->personal:Ljava/lang/String;
    000a: if-eqz p3, # 0040
  [Block #1]
    ; preds: #0
    ; succs: #2, #3
    000c: invoke-static p1, Landroidx/tracing/Trace;->tokenize(Ljava/lang/String;)[Lcom/fsck/k9/mail/helper/Rfc822Token;
    000f: move-result-object p3
    0010: invoke-virtual p3, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    0013: array-length v0, p3
    0014: const-4 v1, #0
    0015: if-nez v0, # 0022
  [Block #2]
    ; preds: #1
    0017: const-4 p0, #1
    0018: new-array p0, p0, [Ljava/lang/Object;
    001a: aput-object p1, p0, v1
    001c: const-string p1, "Invalid address: %s"
    001e: invoke-static p1, p0, Lnet/thunderbird/legacy/logging/Log;->e(Ljava/lang/String;[Ljava/lang/Object;)V
    0021: return-void
  [Block #3]
    ; preds: #1
    ; succs: #4, #5
    0022: aget-object p1, p3, v1
    0024: iget-object p3, p1, Lcom/fsck/k9/mail/helper/Rfc822Token;->mAddress:Ljava/lang/String;
    0026: iput-object p3, p0, Lcom/fsck/k9/mail/Address;->address:Ljava/lang/String;
    0028: iget-object p1, p1, Lcom/fsck/k9/mail/helper/Rfc822Token;->mName:Ljava/lang/String;
    002a: if-eqz p1, # 0032
  [Block #4]
    ; preds: #3
    ; succs: #5, #8
    002c: invoke-virtual p1, Ljava/lang/String;->length()I
    002f: move-result p3
    0030: if-nez p3, # 003e
  [Block #5]
    ; preds: #3, #4
    ; succs: #6, #7
    0032: if-eqz p2, # 003d
  [Block #6]
    ; preds: #5
    ; succs: #8
    0034: invoke-static p2, Lkotlin/text/StringsKt;->trim(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;
    0037: move-result-object p1
    0038: invoke-virtual p1, Ljava/lang/Object;->toString()Ljava/lang/String;
    003b: move-result-object p1
    003c: goto # 003e
  [Block #7]
    ; preds: #5
    ; succs: #8
    003d: const-4 p1, #0
  [Block #8]
    ; preds: #4, #6, #7
    ; succs: #9
    003e: iput-object p1, p0, Lcom/fsck/k9/mail/Address;->personal:Ljava/lang/String;
  [Block #9]
    ; preds: #0, #8
    0040: return-void
.method public final equals(Ljava/lang/Object;)Z
  .registers 6
  [Block #0]
    ; succs: #1, #2
    0000: const-4 v0, #1
    0001: if-ne p0, p1, # 0004
  [Block #1]
    ; preds: #0
    0003: return v0
  [Block #2]
    ; preds: #0
    ; succs: #3, #4
    0004: if-eqz p1, # 000b
  [Block #3]
    ; preds: #2
    ; succs: #5
    0006: invoke-virtual p1, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    0009: move-result-object v1
    000a: goto # 000c
  [Block #4]
    ; preds: #2
    ; succs: #5
    000b: const-4 v1, #0
  [Block #5]
    ; preds: #3, #4
    ; succs: #6, #7
    000c: const-class v2, Lcom/fsck/k9/mail/Address;
    000e: invoke-virtual v2, v1, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z
    0011: move-result v1
    0012: const-4 v2, #0
    0013: if-nez v1, # 0016
  [Block #6]
    ; preds: #5
    0015: return v2
  [Block #7]
    ; preds: #5
    ; succs: #8, #9
    0016: invoke-virtual p1, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    0019: check-cast p1, Lcom/fsck/k9/mail/Address;
    001b: iget-object v1, p0, Lcom/fsck/k9/mail/Address;->address:Ljava/lang/String;
    001d: iget-object v3, p1, Lcom/fsck/k9/mail/Address;->address:Ljava/lang/String;
    001f: invoke-static v1, v3, Lkotlin/jvm/internal/Intrinsics;->areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z
    0022: move-result v1
    0023: if-nez v1, # 0026
  [Block #8]
    ; preds: #7
    0025: return v2
  [Block #9]
    ; preds: #7
    ; succs: #10, #11
    0026: iget-object p0, p0, Lcom/fsck/k9/mail/Address;->personal:Ljava/lang/String;
    0028: iget-object p1, p1, Lcom/fsck/k9/mail/Address;->personal:Ljava/lang/String;
    002a: invoke-static p0, p1, Lkotlin/jvm/internal/Intrinsics;->areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z
    002d: move-result p0
    002e: if-nez p0, # 0031
  [Block #10]
    ; preds: #9
    0030: return v2
  [Block #11]
    ; preds: #9
    0031: return v0
.method public final getHostname()Ljava/lang/String;
  .registers 3
  [Block #0]
    ; succs: #1, #2
    0000: const-string v0, "@"
    0002: const-4 v1, #6
    0003: iget-object p0, p0, Lcom/fsck/k9/mail/Address;->address:Ljava/lang/String;
    0005: invoke-static v1, p0, v0, Lkotlin/text/StringsKt;->lastIndexOf$default(ILjava/lang/CharSequence;Ljava/lang/String;)I
    0008: move-result v0
    0009: const-4 v1, #-1
    000a: if-ne v0, v1, # 000e
  [Block #1]
    ; preds: #0
    000c: const-4 p0, #0
    000d: return-object p0
  [Block #2]
    ; preds: #0
    000e: add-int-lit8 v0, v0, #1
    0010: invoke-virtual p0, v0, Ljava/lang/String;->substring(I)Ljava/lang/String;
    0013: move-result-object p0
    0014: return-object p0
.method public final hashCode()I
  .registers 2
  [Block #0]
    ; succs: #1, #2
    0000: iget-object v0, p0, Lcom/fsck/k9/mail/Address;->address:Ljava/lang/String;
    0002: invoke-virtual v0, Ljava/lang/String;->hashCode()I
    0005: move-result v0
    0006: mul-int-lit8 v0, v0, #31
    0008: iget-object p0, p0, Lcom/fsck/k9/mail/Address;->personal:Ljava/lang/String;
    000a: if-eqz p0, # 0011
  [Block #1]
    ; preds: #0
    ; succs: #3
    000c: invoke-virtual p0, Ljava/lang/String;->hashCode()I
    000f: move-result p0
    0010: goto # 0012
  [Block #2]
    ; preds: #0
    ; succs: #3
    0011: const-4 p0, #0
  [Block #3]
    ; preds: #1, #2
    0012: add-int-2addr v0, p0
    0013: return v0
.method public final toEncodedString()Ljava/lang/String;
  .registers 12
  [Block #0]
    ; succs: #1, #46
    0000: iget-object v0, p0, Lcom/fsck/k9/mail/Address;->address:Ljava/lang/String;
    0002: iget-object p0, p0, Lcom/fsck/k9/mail/Address;->personal:Ljava/lang/String;
    0004: if-eqz p0, # 0101
  [Block #1]
    ; preds: #0
    ; succs: #2, #3
    0006: invoke-static p0, Lkotlin/text/StringsKt;->isBlank(Ljava/lang/CharSequence;)Z
    0009: move-result v1
    000a: if-eqz v1, # 000e
  [Block #2]
    ; preds: #1
    ; succs: #46
    000c: goto-16 # 0101
  [Block #3]
    ; preds: #1
    ; succs: #4
    000e: sget-object v1, Lorg/apache/james/mime4j/codec/EncoderUtil;->BASE64_TABLE:[B
    0010: invoke-virtual p0, Ljava/lang/String;->length()I
    0013: move-result v1
    0014: const-4 v2, #0
    0015: move v3, v2
    0016: move v4, v3
  [Block #4]
    ; preds: #3, #9
    ; succs: #5, #10
    0017: const-4 v5, #1
    0018: if-ge v3, v1, # 0033
  [Block #5]
    ; preds: #4
    ; succs: #6, #7
    001a: invoke-virtual p0, v3, Ljava/lang/String;->charAt(I)C
    001d: move-result v6
    001e: sget-object v7, Lorg/apache/james/mime4j/codec/EncoderUtil;->ATEXT_CHARS:Ljava/util/BitSet;
    0020: invoke-virtual v7, v6, Ljava/util/BitSet;->get(I)Z
    0023: move-result v7
    0024: if-eqz v7, # 0028
  [Block #6]
    ; preds: #5
    ; succs: #9
    0026: move v4, v5
    0027: goto # 0030
  [Block #7]
    ; preds: #5
    ; succs: #8, #9
    0028: invoke-static v6, Lokhttp3/Cookie$Companion;->isWhitespace(C)Z
    002b: move-result v6
    002c: if-nez v6, # 0030
  [Block #8]
    ; preds: #7
    ; succs: #10
    002e: move v4, v2
    002f: goto # 0033
  [Block #9]
    ; preds: #6, #7
    ; succs: #4
    0030: add-int-lit8 v3, v3, #1
    0032: goto # 0017
  [Block #10]
    ; preds: #4, #8
    ; succs: #11, #12
    0033: if-eqz v4, # 0037
  [Block #11]
    ; preds: #10
    ; succs: #45
    0035: goto-16 # 00f8
  [Block #12]
    ; preds: #10
    ; succs: #13
    0037: move v1, v2
    0038: move v3, v1
  [Block #13]
    ; preds: #12, #43
    ; succs: #14, #44
    0039: invoke-virtual p0, Ljava/lang/String;->length()I
    003c: move-result v4
    003d: if-ge v1, v4, # 00d9
  [Block #14]
    ; preds: #13
    ; succs: #15, #42
    003f: invoke-virtual p0, v1, Ljava/lang/String;->charAt(I)C
    0042: move-result v4
    0043: const-16 v6, #9
    0045: if-eq v4, v6, # 00d4
  [Block #15]
    ; preds: #14
    ; succs: #16, #17
    0047: const-16 v6, #32
    0049: if-ne v4, v6, # 004d
  [Block #16]
    ; preds: #15
    ; succs: #42
    004b: goto-16 # 00d4
  [Block #17]
    ; preds: #15
    ; succs: #18, #19
    004d: add-int-2addr v3, v5
    004e: const-16 v7, #77
    0050: const-16 v8, #127
    0052: if-le v3, v7, # 0055
  [Block #18]
    ; preds: #17
    ; succs: #21
    0054: goto # 0059
  [Block #19]
    ; preds: #17
    ; succs: #20, #21
    0055: if-lt v4, v6, # 0059
  [Block #20]
    ; preds: #19
    ; succs: #21, #43
    0057: if-lt v4, v8, # 00d5
  [Block #21]
    ; preds: #18, #19, #20
    ; succs: #22
    0059: invoke-virtual p0, Ljava/lang/String;->length()I
    005c: move-result v1
    005d: move v3, v2
  [Block #22]
    ; preds: #21, #27
    ; succs: #23, #28
    005e: const-16 v4, #255
    0060: if-ge v3, v1, # 0071
  [Block #23]
    ; preds: #22
    ; succs: #24, #25
    0062: invoke-virtual p0, v3, Ljava/lang/String;->charAt(I)C
    0065: move-result v7
    0066: if-le v7, v4, # 006b
  [Block #24]
    ; preds: #23
    ; succs: #31
    0068: sget-object v1, Lorg/apache/james/mime4j/Charsets;->UTF_8:Ljava/nio/charset/Charset;
    006a: goto # 0078
  [Block #25]
    ; preds: #23
    ; succs: #26, #27
    006b: if-le v7, v8, # 006e
  [Block #26]
    ; preds: #25
    ; succs: #27
    006d: move v5, v2
  [Block #27]
    ; preds: #25, #26
    ; succs: #22
    006e: add-int-lit8 v3, v3, #1
    0070: goto # 005e
  [Block #28]
    ; preds: #22
    ; succs: #29, #30
    0071: if-eqz v5, # 0076
  [Block #29]
    ; preds: #28
    ; succs: #31
    0073: sget-object v1, Lorg/apache/james/mime4j/Charsets;->US_ASCII:Ljava/nio/charset/Charset;
    0075: goto # 0078
  [Block #30]
    ; preds: #28
    ; succs: #31
    0076: sget-object v1, Lorg/apache/james/mime4j/Charsets;->ISO_8859_1:Ljava/nio/charset/Charset;
  [Block #31]
    ; preds: #24, #29, #30
    ; succs: #32, #33
    0078: invoke-static p0, v1, Lorg/apache/james/mime4j/codec/EncoderUtil;->encode(Ljava/lang/String;Ljava/nio/charset/Charset;)[B
    007b: move-result-object v3
    007c: array-length v5, v3
    007d: const-string v7, "=?"
    007f: if-nez v5, # 0082
  [Block #32]
    ; preds: #31
    ; succs: #41
    0081: goto # 00ba
  [Block #33]
    ; preds: #31
    ; succs: #34
    0082: sget-object v5, Lorg/apache/james/mime4j/codec/EncoderUtil;->Q_RESTRICTED_CHARS:Ljava/util/BitSet;
    0084: array-length v8, v3
    0085: move v9, v2
  [Block #34]
    ; preds: #33, #38
    ; succs: #35, #39
    0086: if-ge v2, v8, # 0098
  [Block #35]
    ; preds: #34
    ; succs: #36, #38
    0088: aget-byte v10, v3, v2
    008a: and-int-2addr v10, v4
    008b: if-eq v10, v6, # 0095
  [Block #36]
    ; preds: #35
    ; succs: #37, #38
    008d: invoke-virtual v5, v10, Ljava/util/BitSet;->get(I)Z
    0090: move-result v10
    0091: if-nez v10, # 0095
  [Block #37]
    ; preds: #36
    ; succs: #38
    0093: add-int-lit8 v9, v9, #1
  [Block #38]
    ; preds: #35, #36, #37
    ; succs: #34
    0095: add-int-lit8 v2, v2, #1
    0097: goto # 0086
  [Block #39]
    ; preds: #34
    ; succs: #40, #41
    0098: mul-int-lit8 v9, v9, #100
    009a: array-length v2, v3
    009b: div-int-2addr v9, v2
    009c: const-16 v2, #30
    009e: if-le v9, v2, # 00ba
  [Block #40]
    ; preds: #39
    ; succs: #45
    00a0: new-instance v2, Ljava/lang/StringBuilder;
    00a2: invoke-direct v2, v7, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
    00a5: invoke-virtual v1, Ljava/nio/charset/Charset;->name()Ljava/lang/String;
    00a8: move-result-object v4
    00a9: invoke-virtual v2, v4, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    00ac: const-string v4, "?B?"
    00ae: invoke-virtual v2, v4, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    00b1: invoke-virtual v2, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    00b4: move-result-object v2
    00b5: invoke-static v2, p0, v1, v3, Lorg/apache/james/mime4j/codec/EncoderUtil;->encodeB(Ljava/lang/String;Ljava/lang/String;Ljava/nio/charset/Charset;[B)Ljava/lang/String;
    00b8: move-result-object p0
    00b9: goto # 00f8
  [Block #41]
    ; preds: #32, #39
    ; succs: #45
    00ba: new-instance v2, Ljava/lang/StringBuilder;
    00bc: invoke-direct v2, v7, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
    00bf: invoke-virtual v1, Ljava/nio/charset/Charset;->name()Ljava/lang/String;
    00c2: move-result-object v4
    00c3: invoke-virtual v2, v4, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    00c6: const-string v4, "?Q?"
    00c8: invoke-virtual v2, v4, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    00cb: invoke-virtual v2, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    00ce: move-result-object v2
    00cf: invoke-static v2, p0, v1, v3, Lorg/apache/james/mime4j/codec/EncoderUtil;->encodeQ(Ljava/lang/String;Ljava/lang/String;Ljava/nio/charset/Charset;[B)Ljava/lang/String;
    00d2: move-result-object p0
    00d3: goto # 00f8
  [Block #42]
    ; preds: #14, #16
    ; succs: #43
    00d4: move v3, v2
  [Block #43]
    ; preds: #20, #42
    ; succs: #13
    00d5: add-int-lit8 v1, v1, #1
    00d7: goto-16 # 0039
  [Block #44]
    ; preds: #13
    ; succs: #45
    00d9: new-instance v1, Ljava/lang/StringBuilder;
    00db: const-string v2, """
    00dd: invoke-direct v1, v2, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
    00e0: sget-object v2, Lorg/apache/james/mime4j/codec/EncoderUtil;->QUOTE:Ljava/util/regex/Pattern;
    00e2: invoke-virtual v2, p0, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;
    00e5: move-result-object p0
    00e6: const-string v2, "\\$0"
    00e8: invoke-virtual p0, v2, Ljava/util/regex/Matcher;->replaceAll(Ljava/lang/String;)Ljava/lang/String;
    00eb: move-result-object p0
    00ec: invoke-virtual v1, p0, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    00ef: const-16 p0, #34
    00f1: invoke-virtual v1, p0, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;
    00f4: invoke-virtual v1, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    00f7: move-result-object p0
  [Block #45]
    ; preds: #11, #40, #41, #44
    00f8: const-string v1, " <"
    00fa: const-string v2, ">"
    00fc: invoke-static p0, v1, v0, v2, Lcoil3/size/ViewSizeResolver$-CC;->m(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    00ff: move-result-object p0
    0100: return-object p0
  [Block #46]
    ; preds: #0, #2
    0101: return-object v0
.method public final toString()Ljava/lang/String;
  .registers 4
  [Block #0]
    ; succs: #1, #11
    0000: iget-object v0, p0, Lcom/fsck/k9/mail/Address;->address:Ljava/lang/String;
    0002: iget-object p0, p0, Lcom/fsck/k9/mail/Address;->personal:Ljava/lang/String;
    0004: if-eqz p0, # 0041
  [Block #1]
    ; preds: #0
    ; succs: #2, #3
    0006: invoke-static p0, Lkotlin/text/StringsKt;->isBlank(Ljava/lang/CharSequence;)Z
    0009: move-result v1
    000a: if-eqz v1, # 000d
  [Block #2]
    ; preds: #1
    ; succs: #11
    000c: goto # 0041
  [Block #3]
    ; preds: #1
    ; succs: #4, #9
    000d: if-eqz p0, # 0037
  [Block #4]
    ; preds: #3
    ; succs: #5, #6
    000f: sget-object v1, Lcom/fsck/k9/mail/Address;->ATOM:Ljava/util/regex/Pattern;
    0011: invoke-virtual v1, p0, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;
    0014: move-result-object v1
    0015: invoke-virtual v1, Ljava/util/regex/Matcher;->matches()Z
    0018: move-result v1
    0019: if-eqz v1, # 001c
  [Block #5]
    ; preds: #4
    ; succs: #10
    001b: goto # 0038
  [Block #6]
    ; preds: #4
    ; succs: #7, #8
    001c: const-string v1, "^".*"$"
    001e: invoke-static v1, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;
    0021: move-result-object v1
    0022: invoke-virtual v1, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    0025: invoke-virtual v1, p0, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;
    0028: move-result-object v1
    0029: invoke-virtual v1, Ljava/util/regex/Matcher;->matches()Z
    002c: move-result v1
    002d: if-eqz v1, # 0030
  [Block #7]
    ; preds: #6
    ; succs: #10
    002f: goto # 0038
  [Block #8]
    ; preds: #6
    ; succs: #10
    0030: const-string v1, """
    0032: invoke-static v1, p0, v1, Landroidx/camera/camera2/pipe/CameraDevices$-CC;->m(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    0035: move-result-object p0
    0036: goto # 0038
  [Block #9]
    ; preds: #3
    ; succs: #10
    0037: const-4 p0, #0
  [Block #10]
    ; preds: #5, #7, #8, #9
    0038: const-string v1, " <"
    003a: const-string v2, ">"
    003c: invoke-static p0, v1, v0, v2, Lcoil3/size/ViewSizeResolver$-CC;->m(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    003f: move-result-object p0
    0040: return-object p0
  [Block #11]
    ; preds: #0, #2
    0041: return-object v0
