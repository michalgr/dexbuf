.class public final Lcom/fsck/k9/mail/filter/SmtpDataStuffing;
.super Ljava/io/FilterOutputStream;
.field public state:I
.method public final write(I)V
  .registers 5
  [Block #0]
    ; succs: #1, #2
    0000: const-16 v0, #13
    0002: const-4 v1, #1
    0003: if-ne p1, v0, # 0008
  [Block #1]
    ; preds: #0
    ; succs: #9
    0005: iput v1, p0, Lcom/fsck/k9/mail/filter/SmtpDataStuffing;->state:I
    0007: goto # 0023
  [Block #2]
    ; preds: #0
    ; succs: #3, #5
    0008: iget v0, p0, Lcom/fsck/k9/mail/filter/SmtpDataStuffing;->state:I
    000a: const-4 v2, #2
    000b: if-ne v0, v1, # 0014
  [Block #3]
    ; preds: #2
    ; succs: #4, #5
    000d: const-16 v1, #10
    000f: if-ne p1, v1, # 0014
  [Block #4]
    ; preds: #3
    ; succs: #9
    0011: iput v2, p0, Lcom/fsck/k9/mail/filter/SmtpDataStuffing;->state:I
    0013: goto # 0023
  [Block #5]
    ; preds: #2, #3
    ; succs: #6, #8
    0014: const-4 v1, #0
    0015: if-ne v0, v2, # 0021
  [Block #6]
    ; preds: #5
    ; succs: #7, #8
    0017: const-16 v0, #46
    0019: if-ne p1, v0, # 0021
  [Block #7]
    ; preds: #6
    ; succs: #9
    001b: invoke-super p0, v0, Ljava/io/FilterOutputStream;->write(I)V
    001e: iput v1, p0, Lcom/fsck/k9/mail/filter/SmtpDataStuffing;->state:I
    0020: goto # 0023
  [Block #8]
    ; preds: #5, #6
    ; succs: #9
    0021: iput v1, p0, Lcom/fsck/k9/mail/filter/SmtpDataStuffing;->state:I
  [Block #9]
    ; preds: #1, #4, #7, #8
    0023: invoke-super p0, p1, Ljava/io/FilterOutputStream;->write(I)V
    0026: return-void
