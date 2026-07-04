import torch
import torch.nn as nn

class CNNLSTMModel(nn.Module):

    def __init__(self):
        super(CNNLSTMModel, self).__init__()

        self.conv = nn.Conv1d(
            in_channels=46,
            out_channels=16,
            kernel_size=3,
            padding=1
        )

        self.relu = nn.ReLU()

        self.lstm = nn.LSTM(
            input_size=16,
            hidden_size=32,
            num_layers=1,
            batch_first=True
        )

        self.fc = nn.Linear(
            32,
            1
        )

        self.sigmoid = nn.Sigmoid()

    def forward(self, x):

        # x shape:
        # (batch, 5, 46)

        x = x.permute(
            0,
            2,
            1
        )

        # (batch,46,5)

        x = self.conv(x)

        x = self.relu(x)

        # (batch,16,5)

        x = x.permute(
            0,
            2,
            1
        )

        # (batch,5,16)

        x, _ = self.lstm(x)

        x = x[:, -1, :]

        x = self.fc(x)

        x = self.sigmoid(x)

        return x