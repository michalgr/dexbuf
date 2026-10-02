.class public final Lcom/fsck/k9/account/AccountRemover;
.super Ljava/lang/Object;
.field public final avatarImageRepository:Lnet/thunderbird/feature/account/avatar/data/DefaultAvatarImageRepository;
.field public final backendManager:Lcom/fsck/k9/backend/BackendManager;
.field public final localKeyStoreManager:Lcom/fsck/k9/LocalKeyStoreManager;
.field public final localStoreProvider:Lcom/fsck/k9/mailstore/LocalStoreProvider;
.field public final messagingController:Lcom/fsck/k9/controller/MessagingController;
.field public final preferences:Lcom/fsck/k9/Preferences;
.field public final unifiedInboxConfigurator:Lcom/fsck/k9/preferences/UnifiedInboxConfigurator;
.method public constructor <init>(Lcom/fsck/k9/mailstore/LocalStoreProvider;Lcom/fsck/k9/controller/MessagingController;Lcom/fsck/k9/backend/BackendManager;Lcom/fsck/k9/LocalKeyStoreManager;Lcom/fsck/k9/Preferences;Lcom/fsck/k9/preferences/UnifiedInboxConfigurator;Lnet/thunderbird/feature/account/avatar/data/DefaultAvatarImageRepository;)V
  .registers 8
  [Block #0]
    0000: invoke-direct p0, Ljava/lang/Object;-><init>()V
    0003: iput-object p1, p0, Lcom/fsck/k9/account/AccountRemover;->localStoreProvider:Lcom/fsck/k9/mailstore/LocalStoreProvider;
    0005: iput-object p2, p0, Lcom/fsck/k9/account/AccountRemover;->messagingController:Lcom/fsck/k9/controller/MessagingController;
    0007: iput-object p3, p0, Lcom/fsck/k9/account/AccountRemover;->backendManager:Lcom/fsck/k9/backend/BackendManager;
    0009: iput-object p4, p0, Lcom/fsck/k9/account/AccountRemover;->localKeyStoreManager:Lcom/fsck/k9/LocalKeyStoreManager;
    000b: iput-object p5, p0, Lcom/fsck/k9/account/AccountRemover;->preferences:Lcom/fsck/k9/Preferences;
    000d: iput-object p6, p0, Lcom/fsck/k9/account/AccountRemover;->unifiedInboxConfigurator:Lcom/fsck/k9/preferences/UnifiedInboxConfigurator;
    000f: iput-object p7, p0, Lcom/fsck/k9/account/AccountRemover;->avatarImageRepository:Lnet/thunderbird/feature/account/avatar/data/DefaultAvatarImageRepository;
    0011: return-void
.method public final removeBackend(Lnet/thunderbird/core/android/account/LegacyAccountDto;)V
  .registers 6
  [Block #0]
    ; succs: #1
    ; catches: Ljava/lang/Exception; -> #4
    0000: iget-object p0, p0, Lcom/fsck/k9/account/AccountRemover;->backendManager:Lcom/fsck/k9/backend/BackendManager;
    0002: iget-object v0, p1, Lnet/thunderbird/core/android/account/LegacyAccountDto;->id:Lnet/thunderbird/feature/account/AccountId;
    0004: invoke-virtual v0, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    0007: iget-object v1, p0, Lcom/fsck/k9/backend/BackendManager;->backendCache:Ljava/util/LinkedHashMap;
    0009: monitor-enter v1
  [Block #1]
    ; preds: #0
    ; succs: #2
    ; catches: catch-all -> #3
    000a: iget-object v2, p0, Lcom/fsck/k9/backend/BackendManager;->backendCache:Ljava/util/LinkedHashMap;
    000c: iget-object v3, v0, Lnet/thunderbird/feature/account/AccountId;->value:Ljava/lang/Comparable;
    000e: invoke-virtual v3, Ljava/lang/Object;->toString()Ljava/lang/String;
    0011: move-result-object v3
    0012: invoke-interface v2, v3, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;
    0015: move-result-object v2
    0016: check-cast v2, Lcom/fsck/k9/backend/BackendContainer;
  [Block #2]
    ; preds: #1
    ; catches: Ljava/lang/Exception; -> #4
    0018: monitor-exit v1
    0019: invoke-virtual p0, v0, Lcom/fsck/k9/backend/BackendManager;->notifyListeners(Lnet/thunderbird/feature/account/AccountId;)V
    001c: return-void
  [Block #3]
    ; handler for: catch-all
    ; catches: Ljava/lang/Exception; -> #4
    001d: move-exception p0
    001e: monitor-exit v1
    001f: throw p0
  [Block #4]
    ; handler for: Ljava/lang/Exception;
    0020: move-exception p0
    0021: const-string v0, "Failed to reset remote store for account %s"
    0023: const-4 v1, #1
    0024: new-array v1, v1, [Ljava/lang/Object;
    0026: const-4 v2, #0
    0027: aput-object p1, v1, v2
    0029: invoke-static p0, v0, v1, Lnet/thunderbird/legacy/logging/Log;->e(Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V
    002c: return-void