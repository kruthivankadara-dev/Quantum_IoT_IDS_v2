import torch
import torch.nn as nn

class AutoEncoder(nn.Module):

    def __init__(self):

        super().__init__()

        self.encoder = nn.Sequential(
            nn.Linear(230,128),
            nn.ReLU(),
            nn.Linear(128,64)
        )

        self.decoder = nn.Sequential(
            nn.Linear(64,128),
            nn.ReLU(),
            nn.Linear(128,230)
        )

    def forward(self,x):

        latent = self.encoder(x)

        reconstruction = self.decoder(
            latent
        )

        return reconstruction