import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

csv_path = "/home/garlicbread/opcua/opcua_preprocessed.csv"
df = pd.read_csv(csv_path)

df["opcua_payload"] = df["opcua_payload"].apply(lambda x: np.array(eval(x)))  
payload_data = np.stack(df["opcua_payload"].values)  

payload_tensor = torch.tensor(payload_data, dtype=torch.float32)

if len(payload_tensor.shape) == 2:
    num_samples, features = payload_tensor.shape
    payload_tensor = payload_tensor.unsqueeze(1)  
    input_dim = features
    seq_len = 1
else:
    num_samples, seq_len, input_dim = payload_tensor.shape

class VAE(nn.Module):
    def __init__(self, input_dim, hidden_dim=128, latent_dim=16, seq_len=1):
        super(VAE, self).__init__()
        self.seq_len = seq_len
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim
        
        self.encoder = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        self.fc_mu = nn.Linear(hidden_dim, latent_dim)
        self.fc_logvar = nn.Linear(hidden_dim, latent_dim)
        
        self.fc_decoder = nn.Linear(latent_dim, hidden_dim)
        self.decoder = nn.LSTM(hidden_dim, hidden_dim, batch_first=True)
        self.output_layer = nn.Linear(hidden_dim, input_dim)

    def encode(self, x):
        _, (h, _) = self.encoder(x)
        h = h[-1]  
        
        mu = self.fc_mu(h)
        logvar = self.fc_logvar(h)
        return mu, logvar

    def reparameterize(self, mu, logvar):
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std

    def decode(self, z):
        batch_size = z.size(0)
        
        h0 = self.fc_decoder(z).unsqueeze(0)  
        
        decoder_input = torch.zeros(batch_size, self.seq_len, self.hidden_dim, device=z.device)
        
        c0 = torch.zeros_like(h0)
        
        output, _ = self.decoder(decoder_input, (h0, c0))
        
        reconstructed = self.output_layer(output)
        return reconstructed

    def forward(self, x):
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        return self.decode(z), mu, logvar

latent_dim = 16
hidden_dim = 128
model = VAE(input_dim=input_dim, hidden_dim=hidden_dim, latent_dim=latent_dim, seq_len=seq_len)

optimizer = optim.Adam(model.parameters(), lr=0.001)
criterion = nn.MSELoss()

dataset = TensorDataset(payload_tensor)
dataloader = DataLoader(dataset, batch_size=32, shuffle=True)

num_epochs = 10
for epoch in range(num_epochs):
    total_loss = 0
    for batch in dataloader:
        x = batch[0]
        optimizer.zero_grad()
        
        recon_x, mu, logvar = model(x)
        
        recon_loss = criterion(recon_x, x)
        kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
        loss = recon_loss + kl_loss
        
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
    
    print(f"Epoch {epoch+1}/{num_epochs}, Loss: {total_loss:.4f}")

torch.save(model.state_dict(), "opcua_vae.pth")
print("Model training complete. Saved to opcua_vae.pth")

model.eval()
with torch.no_grad():
    sample_data = next(iter(dataloader))[0]
    recon, _, _ = model(sample_data)
    
    mse = nn.MSELoss(reduction='none')(recon, sample_data).mean(dim=[1, 2])
    print(f"Average reconstruction MSE: {mse.mean().item():.6f}")
    
