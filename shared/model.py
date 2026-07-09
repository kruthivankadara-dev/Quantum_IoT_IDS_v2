import torch
import torch.nn as nn


class CNNLSTMModel(nn.Module):

    def __init__(self, input_features=46):
        super(CNNLSTMModel, self).__init__()

        # -------------------------
        # Feature Extraction
        # -------------------------

        self.conv1 = nn.Conv1d(
            in_channels=input_features,
            out_channels=64,
            kernel_size=3,
            padding=1
        )

        self.bn1 = nn.BatchNorm1d(64)

        self.conv2 = nn.Conv1d(
            in_channels=64,
            out_channels=128,
            kernel_size=3,
            padding=1
        )

        self.bn2 = nn.BatchNorm1d(128)

        self.relu = nn.ReLU(inplace=True)

        self.dropout = nn.Dropout(0.3)

        # -------------------------
        # Sequence Model
        # -------------------------

        self.lstm = nn.LSTM(
            input_size=128,
            hidden_size=128,
            num_layers=2,
            batch_first=True,
            bidirectional=True,
            dropout=0.3
        )

        # -------------------------
        # Classifier
        # -------------------------

        self.classifier = nn.Sequential(

            nn.Linear(256, 128),

            nn.ReLU(inplace=True),

            nn.Dropout(0.4),

            nn.Linear(128, 64),

            nn.ReLU(inplace=True),

            nn.Dropout(0.3),

            nn.Linear(64, 1)

        )

        self._initialize_weights()

    # ------------------------------------------------

    def _initialize_weights(self):

        for m in self.modules():

            if isinstance(m, nn.Conv1d):

                nn.init.kaiming_normal_(
                    m.weight,
                    nonlinearity="relu"
                )

                if m.bias is not None:
                    nn.init.zeros_(m.bias)

            elif isinstance(m, nn.Linear):

                nn.init.xavier_uniform_(m.weight)

                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    # ------------------------------------------------

    def forward(self, x):

        # Input
        # (batch, window, features)

        x = x.permute(0, 2, 1)

        # -------------------------

        x = self.conv1(x)

        x = self.bn1(x)

        x = self.relu(x)

        x = self.dropout(x)

        # -------------------------

        x = self.conv2(x)

        x = self.bn2(x)

        x = self.relu(x)

        x = self.dropout(x)

        # -------------------------

        x = x.permute(0, 2, 1)

        # (batch, window, channels)

        lstm_out, _ = self.lstm(x)

        last = lstm_out[:, -1, :]

        logits = self.classifier(last)

        return logits