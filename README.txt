‎Title – A Hybrid LSTM-DQN Framework with Neutrosophic Logic for Detection of Network Intrusions

‎Description – Network security is still at risk from denial of service (DoS) and distributed denial of service (DDoS) attacks, which have evolved to imitate legal traffic and take advantage of detection system flaws. These complex methods, data scarcity, and the crucial requirement for real-time adaptation frequently cause traditional and deep learning-based intrusion detection systems (IDS) to falter. A sequential technique to network intrusion detection is proposed in the study. Cleaning, normalization, balancing, and feature reduction are the first steps in the data preprocessing process. A proprietary Generative Adversarial Network (GAN) is used to create synthetic attack traffic samples to collect fake data. The multiple heterogeneous datasets are used to quantify uncertainty as membership values for Truth (T), Indeterminacy (I), and Falsity (F) using the Neutrosophic Logic transformation (NL). A hybrid deep learning model that integrates a Long Short-Term Memory (LSTM) network to learn temporal dependencies and a Deep Q-Networks (DQN) for adaptive decision-making receives the processed data. 

Dataset Information - This study uses four public network datasets—NSL-KDD, UNSW-NB15, TON-IoT, and CIC-IDS2018—covering traditional and modern enterprise, IoT/IIoT, and cloud environments. Multiple datasets include (125,972 instances, 43 attributes) was chosen for its labeling and attack variety (DoS, U2R, R2L). UNSW-NB15 models modern enterprise attacks, TON-IoT represents heterogeneous, imbalanced IoT/IIoT data, and CIC-IDS2018 simulates large-scale enterprise/cloud (notably application-layer DDoS).

‎Code Information - using python colab

Explain code - 
Load Dataset & Initial Cleaning : 

df_0 = pd.read_csv("/kaggle/input/unsw-nb15-dataset/UNSW-NB15_c/UNSW_NB15_testing-set.csv")
df = df_0.copy()
df.drop(columns=['id'], inplace=True, errors='ignore')

Feature Selection
from sklearn.feature_selection import mutual_info_classif
mutual_info = mutual_info_classif(X_train, y_train)
mutual_info.index = train_index
mutual_info.sort_values(ascending=False)

Select Top K Features
from sklearn.feature_selection import SelectKBest

Select_features = SelectKBest(mutual_info_classif, k=30)
Select_features.fit(X_train, y_train)

train_index[Select_features.get_support()]

Feature Scaling
from sklearn.preprocessing import StandardScaler

scaler = StandardScaler()

X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

GAN for Synthetic Attack Generation
class Generator(nn.Module):
Discriminator
class Discriminator(nn.Module):
def train_gan(generator, discriminator, data, noise_dim, ...)
noise = torch.randn(num_samples, noise_dim)
synthetic_attacks = G(noise).detach().numpy()
synthetic_attacks_rescaled = scaler.inverse_transform(synthetic_attacks)


LSTM Model for Intrusion Detection
def create_lstm_model():
LSTM(64 units)
Dense(1, sigmoid)

Neutrosophic Logic
T = proba_normal
F = 1 - T
I = 1 - abs(2*T - 1)


Evaluation
mask = final_preds != -1
accuracy 


.........................................
Usage Instructions – How to use or load the dataset and code- 
------------------------------------------------------------
INPUT: NSL-KDD, UNSW-NB15, TON-IoT, and CIC-IDS2018 datasets D (125,972 samples, 43 features)
OUTPUT: Predictions, Performance metrics
Parameters: epochs = 20, batch size = 64, γ = 0.95, ε = 1.0
Begin:
# Stage 1: Data Preprocessing
    1: Load dataset D
    2: Clean data: remove missing values and outliers
    3: Normalize numerical features using min-max scaling
    4: Encode categorical features using one-hot encoding
    5: Split dataset: D_train (80%), D_test (20%)
 
    # Stage 2: GAN-Based Augmentation
    6: Initialize Generator G(z) and Discriminator D(x)
    7: For gan_epoch = 1 to 100 do
           // Apply Equ (1): min_G max_D V(D,G) = E[log D(x)] + E[log(1-D(G(z)))]
           Train D to maximize: log D(x_real) + log(1 - D(G(z)))
           Train G to minimize: log(1 - D(G(z)))
    8: Generate synthetic attack samples using trained G
    9: Balance datasets with synthetic samples → D_balanced
 
    # Stage 3: Neutrosophic Transformation
    10: For each sample x in D_balanced do
            Calculate T(x) = confidence score (benign probability)
            // Apply Equ (2): I(x) = 1 - (ConfidenceScore / max(FeatureRange))
            Calculate I(x) = uncertainty measure
            Calculate F(x) = 1 - T(x) (malicious probability)
            Transform x → x_neutro = [T(x), I(x), F(x)]
 
    # Stage 4: Initialize Models
    11: Build LSTM network (hidden_size=128, layers=2, dropout=0.3)
    12: Build Q_network (state_size=3, action_size=3: block/allow/inspect)
    13: Build Target_network ← copy of Q_network
    14: Initialize ReplayBuffer (capacity=2000)
 
    # Stage 5: Hybrid Training
    15: For epoch = 1 to epochs do
    16.     For each batch in D_train do
                // LSTM Temporal Analysis
    17:        For each timestep t do
                    // Apply Equs (3-8) for LSTM gates:
                    f_t ← sigmoid(W_f * [h_{t-1}, x_t] + b_f)                       // Eq. (3): Forget gate
                    i_t ← sigmoid(W_i * [h_{t-1}, x_t] + b_i)                       // Eq. (4): Input gate
                    c̃_t ← tanh(W_c * [h_{t-1}, x_t] + b_c)                            // Eq. (6): Candidate state
                    c_t ← f_t * c_{t-1} + i_t * c̃_t                                                // Eq. (7): Cell state
                    o_t ← sigmoid(W_o * [h_{t-1}, x_t] + b_o)                    // Eq. (5): Output gate
                    h_t ← o_t * tanh(c_t)                                                             // Eq. (8): Hidden state
 

                // DQN Decision Making
    18:      For each sample i with state s_i = [T_i, I_i, F_i] do
                       If random() < ε: a_i ← random action
                       Else: a_i ← argmax Q_network(s_i)
    19:             Execute action a_i (0=block, 1= allow, 2=inspect)
    20:             Calculate reward: r_i = +1 (correct), 0 (inspect), -1 (incorrect)
    21:             Store transition (s_i, a_i, r_i, s'_i) in ReplayBuffer
 
                // Model Updates
    22:      Update LSTM: Backpropagate CrossEntropy loss
    23:       Sample mini_batch from ReplayBuffer
    24:       For each (s, a, r, s') in mini_batch do
                         // Apply Equ (9): Bellman equation
                         target_Q ← r + γ × max_{a'} Q*(s', a')
                         Update Q_network using MSE loss
    25:         Decay ε ← max(0.01, ε × 0.995)
    26:         If epoch % 5 == 0: Update Target_network ← Q_network
    27:     If early stopping criteria met: Break
 
    # Stage 6: Testing & Evaluation
    28: For each sample x in D_test do
                   h_t ← LSTM.Forward(x)
                   action ← argmax Q_network([T(x), I(x), F(x)])
                   prediction ← Map action to class (malicious/benign)
        29: Performance metrics:
         Prec ←T_(P )/(T_P+F_P)
         Rec ←T_(P )/(T_P+F_N)
         F1 ←2×(Prec×Rec)  / (Prec+Rec)
         Acc←(T_P+T_N)/(T_P+T_N+F_P+T_N)
 
    30: Return predictions, {Accuracy, Recall, F1-Score}
End


..................................


Citations (if applicable) – If this dataset was used in research, provide references -  
Data Availability Statement: We use open data from Kaggle 
- NSL-KDD dataset, The link is https://www.kaggle.com/datasets/hassan06/nslkdd. 
- UNSW-NB15 dataset, Link: https://www.kaggle.com/datasets/freshersstaff/unsw-nb15-dataset, 
- TON_IoT Dataset, Link: https://www.kaggle.com/datasets/shahidabbas76/train-test-network-csv , 
- CIC-IDS2018 dataset, Link:  https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv.

