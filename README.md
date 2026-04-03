A Hybrid LSTM-DQN Framework with Neutrosophic Logic for Detection of Network Intrusions











.........................................

INPUT: NSL-KDD, UNSW-NB15, TON-IoT, and CIC-IDS2018 datasets D (125,972 samples, 43 features)

OUTPUT: Predictions, Performance metrics

Parameters: epochs = 20, batch size = 64, γ = 0.95, ε = 1.0

Begin:

\# Stage 1: Data Preprocessing 

&#x20;   1: Load dataset D

&#x20;   2: Clean data: remove missing values and outliers

&#x20;   3: Normalize numerical features using min-max scaling

&#x20;   4: Encode categorical features using one-hot encoding

&#x20;   5: Split dataset: D\_train (80%), D\_test (20%)

&#x20;   

&#x20;   # Stage 2: GAN-Based Augmentation 

&#x20;   6: Initialize Generator G(z) and Discriminator D(x)

&#x20;   7: For gan\_epoch = 1 to 100 do

&#x20;          // Apply Equ (1): min\_G max\_D V(D,G) = E\[log D(x)] + E\[log(1-D(G(z)))]

&#x20;          Train D to maximize: log D(x\_real) + log(1 - D(G(z)))

&#x20;          Train G to minimize: log(1 - D(G(z)))

&#x20;   8: Generate synthetic attack samples using trained G

&#x20;   9: Balance datasets with synthetic samples → D\_balanced

&#x20;   

&#x20;   # Stage 3: Neutrosophic Transformation 

&#x20;   10: For each sample x in D\_balanced do

&#x20;           Calculate T(x) = confidence score (benign probability)

&#x20;           // Apply Equ (2): I(x) = 1 - (ConfidenceScore / max(FeatureRange))

&#x20;           Calculate I(x) = uncertainty measure

&#x20;           Calculate F(x) = 1 - T(x) (malicious probability)

&#x20;           Transform x → x\_neutro = \[T(x), I(x), F(x)]

&#x20;   

&#x20;   # Stage 4: Initialize Models 

&#x20;   11: Build LSTM network (hidden\_size=128, layers=2, dropout=0.3)

&#x20;   12: Build Q\_network (state\_size=3, action\_size=3: block/allow/inspect)

&#x20;   13: Build Target\_network ← copy of Q\_network

&#x20;   14: Initialize ReplayBuffer (capacity=2000)

&#x20;   

&#x20;   # Stage 5: Hybrid Training 

&#x20;   15: For epoch = 1 to epochs do

&#x20;   16.     For each batch in D\_train do

&#x20;               // LSTM Temporal Analysis 

&#x20;   17:        For each timestep t do

&#x20;                   // Apply Equs (3-8) for LSTM gates:

&#x20;                   f\_t ← sigmoid(W\_f \* \[h\_{t-1}, x\_t] + b\_f)                       // Eq. (3): Forget gate

&#x20;                   i\_t ← sigmoid(W\_i \* \[h\_{t-1}, x\_t] + b\_i)                       // Eq. (4): Input gate

&#x20;                   c̃\_t ← tanh(W\_c \* \[h\_{t-1}, x\_t] + b\_c)                            // Eq. (6): Candidate state

&#x20;                   c\_t ← f\_t \* c\_{t-1} + i\_t \* c̃\_t                                                // Eq. (7): Cell state

&#x20;                   o\_t ← sigmoid(W\_o \* \[h\_{t-1}, x\_t] + b\_o)                    // Eq. (5): Output gate

&#x20;                   h\_t ← o\_t \* tanh(c\_t)                                                             // Eq. (8): Hidden state

&#x20;               



&#x20;               // DQN Decision Making 

&#x20;   18:      For each sample i with state s\_i = \[T\_i, I\_i, F\_i] do

&#x20;                      If random() < ε: a\_i ← random action

&#x20;                      Else: a\_i ← argmax Q\_network(s\_i)

&#x20;   19:             Execute action a\_i (0=block, 1= allow, 2=inspect)

&#x20;   20:             Calculate reward: r\_i = +1 (correct), 0 (inspect), -1 (incorrect)

&#x20;   21:             Store transition (s\_i, a\_i, r\_i, s'\_i) in ReplayBuffer

&#x20;               

&#x20;               // Model Updates 

&#x20;   22:      Update LSTM: Backpropagate CrossEntropy loss

&#x20;   23:       Sample mini\_batch from ReplayBuffer

&#x20;   24:       For each (s, a, r, s') in mini\_batch do

&#x20;                        // Apply Equ (9): Bellman equation

&#x20;                        target\_Q ← r + γ × max\_{a'} Q\*(s', a')

&#x20;                        Update Q\_network using MSE loss

&#x20;   25:         Decay ε ← max(0.01, ε × 0.995)

&#x20;   26:         If epoch % 5 == 0: Update Target\_network ← Q\_network

&#x20;   27:     If early stopping criteria met: Break

&#x20;   

&#x20;   # Stage 6: Testing \& Evaluation 

&#x20;   28: For each sample x in D\_test do

&#x20;                  h\_t ← LSTM.Forward(x)

&#x20;                  action ← argmax Q\_network(\[T(x), I(x), F(x)])

&#x20;                  prediction ← Map action to class (malicious/benign)

&#x20;       29: Performance metrics:

&#x20;        Prec ←T\_(P )/(T\_P+F\_P) 

&#x20;        Rec ←T\_(P )/(T\_P+F\_N) 

&#x20;        F1 ←2×(Prec×Rec)  / (Prec+Rec)  

&#x20;        Acc←(T\_P+T\_N)/(T\_P+T\_N+F\_P+T\_N) 

&#x20;   

&#x20;   30: Return predictions, {Accuracy, Recall, F1-Score}

End





..................................





Load Dataset \& Initial Cleaning



df\_0 = pd.read\_csv("/kaggle/input/unsw-nb15-dataset/UNSW-NB15\_c/UNSW\_NB15\_testing-set.csv")

df = df\_0.copy()

df.drop(columns=\['id'], inplace=True, errors='ignore')



Feature Selection

from sklearn.feature\_selection import mutual\_info\_classif

mutual\_info = mutual\_info\_classif(X\_train, y\_train)

mutual\_info.index = train\_index

mutual\_info.sort\_values(ascending=False)



Select Top K Features

from sklearn.feature\_selection import SelectKBest



Select\_features = SelectKBest(mutual\_info\_classif, k=30)

Select\_features.fit(X\_train, y\_train)



train\_index\[Select\_features.get\_support()]



Feature Scaling

from sklearn.preprocessing import StandardScaler



scaler = StandardScaler()



X\_train = scaler.fit\_transform(X\_train)

X\_test = scaler.transform(X\_test)



GAN for Synthetic Attack Generation

class Generator(nn.Module):

Discriminator

class Discriminator(nn.Module):

def train\_gan(generator, discriminator, data, noise\_dim, ...)

noise = torch.randn(num\_samples, noise\_dim)

synthetic\_attacks = G(noise).detach().numpy()

synthetic\_attacks\_rescaled = scaler.inverse\_transform(synthetic\_attacks)





LSTM Model for Intrusion Detection

def create\_lstm\_model():

LSTM(64 units)

Dense(1, sigmoid)



Neutrosophic Logic

T = proba\_normal

F = 1 - T

I = 1 - abs(2\*T - 1)





Evaluation

mask = final\_preds != -1

accuracy = ...























