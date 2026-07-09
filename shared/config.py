# ==========================================
# NETWORK CONFIGURATION
# ==========================================

EDGE_PORT = 5001
CLOUD_PORT = 8001

# ==========================================
# AI THRESHOLDS
# ==========================================

THREAT_THRESHOLD = 0.65
RECONSTRUCTION_THRESHOLD = 0.08

# ==========================================
# MODEL PATHS
# ==========================================

MODEL_PATH = "models/cnn_lstm.pth"
AUTOENCODER_PATH = "models/autoencoder.pth"
SCALER_PATH = "models/scaler.save"

# ==========================================
# CLOUD FILES
# ==========================================

REPLAY_BUFFER_PATH = "models/replay_buffer.pt"
REGISTRY_PATH = "models/registry.json"

# ==========================================
# CONTINUAL LEARNING
# ==========================================

BATCH_RETRAIN_TRIGGER = 50
LEARNING_RATE = 0.0005
LOCAL_EPOCHS = 3

# ==========================================
# BENIGN SUMMARY SETTINGS
# ==========================================

# Send benign summary every 5 minutes
SUMMARY_INTERVAL = 300

# Upload immediately if this many benign
# packets are collected before 5 minutes
MAX_BENIGN_PACKETS = 1000

# Number of representative benign packets
# kept using Reservoir Sampling
RESERVOIR_SIZE = 20

# ==========================================
# CLOUD RETRY
# ==========================================

MAX_RETRY = 5
RETRY_DELAY = 5

# ==========================================
# STREAMING STATISTICS
# ==========================================

FEATURE_COUNT = 46
WINDOW_SIZE = 10

# ==========================================
# LOGGING
# ==========================================

PRINT_BENIGN = True
PRINT_ATTACK = True
PRINT_SUMMARY = True

# ==========================================
# MODEL UPDATE
# ==========================================

CHECK_MODEL_UPDATE = True


# ==========================================
# SELF HEALING
# ==========================================

ENABLE_SELF_HEALING = True

MAX_ATTACKS = 2

DEVICE_REGISTRY_PATH = "models/device_registry.json"

BLOCK_RESPONSE_CODE = 403