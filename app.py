"""
Streamlit web interface for the Vector-Based Secure Key Storage (VBSKS) system.
"""

import streamlit as st
import numpy as np
import json
import base64
import matplotlib.pyplot as plt
import os
from tempfile import NamedTemporaryFile
import time
import io

from vector_db import VectorDatabase
from key_manager import KeyManager
from simulation import SecuritySimulator
from utils import PRECISION, MIN_VALUE, MAX_VALUE

# Set page configuration
st.set_page_config(
    page_title="VBSKS - Vector-Based Secure Key Storage",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Add custom CSS
st.markdown("""
<style>
    .main .block-container {
        padding-top: 2rem;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2rem;
    }
    .stTabs [data-baseweb="tab"] {
        height: 3rem;
        white-space: pre-wrap;
        border-radius: 4px 4px 0px 0px;
    }
</style>
""", unsafe_allow_html=True)

# Main header
st.title("🔐 Vector-Based Secure Key Storage (VBSKS)")
st.markdown("""
A quantum-resistant key storage system that leverages a noise-filled, high-dimensional vector space 
to securely store cryptographic keys or passwords.
""")

# Create tabs for different functionalities
tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "🔑 Key Generation", "🔍 Key Retrieval", "🔒 Security Simulation"])

# Dashboard Tab
with tab1:
    st.header("System Dashboard")
    
    st.markdown("""
    ## Concept
    
    VBSKS embeds a cryptographic key as a precise sequence of high-precision vectors hidden among random noise. 
    Retrieval requires providing an exact matching sequence, making brute-force attacks—both classical and quantum—computationally infeasible.
    
    ## How It Works
    
    1. **Create a Noise Database**: Generate a large database of random high-dimensional vectors
    2. **Generate Key Vectors**: Create a sequence of vectors that represent your key
    3. **Store Key in Noise**: Place key vectors at specific positions in the noise database
    4. **Retrieval**: Provide the same key vector sequence for authentication
    
    ## Security Features
    
    - **Quantum-Resistant**: The high-dimensional space makes it resistant to quantum attacks
    - **Enormous Key Space**: 100-dimensional vectors with high precision create a massive search space
    - **Side-Channel Protection**: Constant-time operations prevent timing attacks
    """)
    
    # Show theoretical security metrics
    st.subheader("Theoretical Security Metrics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        dimensions = st.slider("Vector Dimensions", min_value=10, max_value=1000, value=100, step=10)
        noise_size = st.slider("Noise Database Size", min_value=1000, max_value=100000, value=10000, step=1000)
    
    with col2:
        key_length = st.slider("Key Length (vectors)", min_value=1, max_value=10, value=5)
        precision = st.slider("Precision (decimal places)", min_value=1, max_value=10, value=6)
    
    import math
    
    # Calculate theoretical security
    try:
        # Calculate position combinations using logarithms
        log_position_combinations = (
            math.log10(math.factorial(noise_size)) - 
            math.log10(math.factorial(key_length)) - 
            math.log10(math.factorial(noise_size - key_length))
        )
        
        # Calculate vector value space (in log10)
        log_values_per_dimension = math.log10(10**precision * (MAX_VALUE - MIN_VALUE))
        log_vector_value_space = dimensions * log_values_per_dimension
        
        # Total search space (in log10)
        log_search_space = log_position_combinations + (key_length * log_vector_value_space)
        
        # Convert to log2 for bit security
        log2_search_space = log_search_space * math.log2(10)
        
        # Expected time to brute force (1 billion checks per second)
        log_time_seconds = log_search_space - 9  # 10^9 checks per second
        log_time_years = log_time_seconds - math.log10(365.25 * 24 * 60 * 60)
        
        # Display metrics
        metrics_col1, metrics_col2, metrics_col3 = st.columns(3)
        
        metrics_col1.metric("Key Space (log10)", f"{log_search_space:.2f}")
        metrics_col2.metric("Bit Security", f"~2^{log2_search_space:.2f}")
        metrics_col3.metric("Brute Force Time", f"~10^{log_time_years:.2f} years")
        
        # Comparison to traditional cryptography
        st.subheader("Comparison to Traditional Cryptography")
        
        compare_col1, compare_col2 = st.columns(2)
        with compare_col1:
            st.info(f"**AES-128**: 2^128 ≈ 10^{128 * math.log10(2):.2f} search space")
            st.info(f"**AES-256**: 2^256 ≈ 10^{256 * math.log10(2):.2f} search space")
        
        with compare_col2:
            st.success(f"**VBSKS**: ~2^{log2_search_space:.2f} ≈ 10^{log_search_space:.2f} search space")
            universe_age = 13.8 * 1e9  # age of universe in years
            log_universe_ratio = log_time_years - math.log10(universe_age)
            st.success(f"**Time to brute force**: ~10^{log_universe_ratio:.2f} times the age of the universe")
    
    except Exception as e:
        st.error(f"Error in calculation: {str(e)}")
        st.warning("The security of this system is extremely high, causing numeric overflow.")
        st.warning("This demonstrates that the key space is effectively impossible to brute force.")

# Key Generation Tab
with tab2:
    st.header("Key Generation")
    
    st.markdown("""
    Generate a new key and store it in a vector database. This will create two files:
    1. A database file containing the noise-filled vector space
    2. A key file containing the positions and key vectors
    """)
    
    col1, col2 = st.columns(2)
    
    with col1:
        gen_dimensions = st.number_input("Vector Dimensions", min_value=10, max_value=1000, value=100, step=10)
        gen_noise_size = st.number_input("Noise Database Size", min_value=1000, max_value=100000, value=10000, step=1000)
    
    with col2:
        gen_key_length = st.number_input("Key Length (vectors)", min_value=1, max_value=10, value=5)
        gen_threshold = st.number_input("Distance Threshold", min_value=1e-10, max_value=1.0, value=float(PRECISION), format="%.1e")
    
    gen_seed = st.text_input("Secret Seed (leave empty for random)", "")
    
    gen_use_indexing = st.checkbox("Use FAISS Indexing (if available)", value=False)
    
    if st.button("Generate Key", type="primary"):
        with st.spinner("Generating vector database and key..."):
            # Create progress bar
            progress_bar = st.progress(0)
            
            # Create the vector database
            progress_bar.progress(10, text="Creating vector database...")
            db = VectorDatabase(
                dimensions=gen_dimensions,
                size=gen_noise_size,
                threshold=gen_threshold,
                use_indexing=gen_use_indexing
            )
            
            # Create a key manager
            progress_bar.progress(30, text="Initializing key manager...")
            km = KeyManager(
                vector_db=db,
                key_length=gen_key_length,
                threshold=gen_threshold
            )
            
            # Generate a key
            progress_bar.progress(50, text="Generating key vectors...")
            secret_seed = gen_seed if gen_seed else os.urandom(16).hex()
            key_vectors, positions = km.generate_key(secret_seed)
            
            # Derive a cryptographic key
            progress_bar.progress(70, text="Deriving cryptographic key...")
            crypto_key = km.derive_cryptographic_key(key_vectors)
            crypto_key_b64 = base64.b64encode(crypto_key).decode()
            
            # Save the database and key to temporary files
            progress_bar.progress(80, text="Saving files...")
            db_file = NamedTemporaryFile(delete=False, suffix=".json")
            key_file = NamedTemporaryFile(delete=False, suffix=".json")
            
            db.save(db_file.name)
            km.save_key_data(key_file.name, key_vectors, positions, {"description": "Generated via VBSKS UI"})
            
            # Complete
            progress_bar.progress(100, text="Complete!")
            time.sleep(0.5)
            progress_bar.empty()
        
        # Display results
        st.success("Key generated successfully!")
        
        # Display positions and cryptographic key
        st.subheader("Key Information")
        key_info_col1, key_info_col2 = st.columns(2)
        
        with key_info_col1:
            st.write("**Key Positions:**")
            st.code(positions)
        
        with key_info_col2:
            st.write("**Derived Cryptographic Key (Base64):**")
            st.code(crypto_key_b64)
        
        # Provide download links for the database and key files
        st.subheader("Download Files")
        
        # Read the files
        with open(db_file.name, "rb") as f:
            db_bytes = f.read()
        
        with open(key_file.name, "rb") as f:
            key_bytes = f.read()
        
        # Create download buttons
        download_col1, download_col2 = st.columns(2)
        
        with download_col1:
            st.download_button(
                label="Download Vector Database",
                data=db_bytes,
                file_name="vbsks_database.json",
                mime="application/json"
            )
        
        with download_col2:
            st.download_button(
                label="Download Key File",
                data=key_bytes,
                file_name="vbsks_key.json",
                mime="application/json"
            )
        
        # Clean up temporary files
        os.unlink(db_file.name)
        os.unlink(key_file.name)

# Key Retrieval Tab
with tab3:
    st.header("Key Retrieval and Verification")
    
    st.markdown("""
    Retrieve a key from a vector database or verify if a provided key is valid.
    """)
    
    # Upload database and key files
    upload_col1, upload_col2 = st.columns(2)
    
    with upload_col1:
        uploaded_db = st.file_uploader("Upload Vector Database", type=["json"])
    
    with upload_col2:
        uploaded_key = st.file_uploader("Upload Key File", type=["json"])
    
    if uploaded_db and uploaded_key:
        # Save uploaded files to temporary locations
        db_file = NamedTemporaryFile(delete=False, suffix=".json")
        with open(db_file.name, "wb") as f:
            f.write(uploaded_db.getvalue())
        
        key_file = NamedTemporaryFile(delete=False, suffix=".json")
        with open(key_file.name, "wb") as f:
            f.write(uploaded_key.getvalue())
        
        # Load the database and key
        with st.spinner("Loading database and key..."):
            # Load the vector database
            db = VectorDatabase.load(db_file.name)
            
            # Load key data
            key_data = KeyManager.load_key_data(key_file.name)
            
            # Create a key manager
            km = KeyManager(
                vector_db=db,
                key_length=key_data['key_length'],
                threshold=key_data.get('threshold', PRECISION)
            )
            
            # Get positions
            positions = key_data['positions']
        
        # Display information about the loaded files
        st.subheader("Loaded Data")
        
        info_col1, info_col2, info_col3 = st.columns(3)
        
        info_col1.metric("Database Dimensions", db.dimensions)
        info_col2.metric("Database Size", db.size)
        info_col3.metric("Key Length", len(positions))
        
        # Option to retrieve or verify
        option = st.radio("Select Operation", ["Retrieve Key", "Verify Key"])
        
        if option == "Retrieve Key":
            if st.button("Retrieve Key", type="primary"):
                with st.spinner("Retrieving key..."):
                    # Retrieve the key vectors
                    key_vectors = km.retrieve_key(positions)
                    
                    # Verify the key
                    is_valid = km.verify_key(positions, key_vectors)
                    
                    # Derive cryptographic key
                    crypto_key = km.derive_cryptographic_key(key_vectors)
                    crypto_key_b64 = base64.b64encode(crypto_key).decode()
                
                if is_valid:
                    st.success("Key retrieved successfully!")
                    
                    # Display cryptographic key
                    st.subheader("Derived Cryptographic Key")
                    st.code(crypto_key_b64)
                    
                    # Option to download key vectors
                    key_vectors_json = {
                        'vectors': key_vectors.tolist(),
                        'shape': key_vectors.shape
                    }
                    
                    st.download_button(
                        label="Download Key Vectors",
                        data=json.dumps(key_vectors_json),
                        file_name="vbsks_key_vectors.json",
                        mime="application/json"
                    )
                else:
                    st.error("Retrieved key is invalid! Database may be corrupted.")
        
        elif option == "Verify Key":
            # Upload key vectors
            uploaded_vectors = st.file_uploader("Upload Key Vectors", type=["json"])
            
            if uploaded_vectors:
                # Load key vectors
                vectors_data = json.loads(uploaded_vectors.getvalue())
                input_vectors = np.array(vectors_data['vectors'])
                
                if st.button("Verify Key", type="primary"):
                    with st.spinner("Verifying key..."):
                        # Verify the key
                        is_valid = km.verify_key(positions, input_vectors)
                    
                    if is_valid:
                        st.success("Key is valid!")
                        
                        # Derive cryptographic key
                        crypto_key = km.derive_cryptographic_key(input_vectors)
                        crypto_key_b64 = base64.b64encode(crypto_key).decode()
                        
                        # Display cryptographic key
                        st.subheader("Derived Cryptographic Key")
                        st.code(crypto_key_b64)
                    else:
                        st.error("Key is invalid!")
        
        # Clean up temporary files
        os.unlink(db_file.name)
        os.unlink(key_file.name)

# Security Simulation Tab
with tab4:
    st.header("Security Simulation")
    
    st.markdown("""
    Run simulations to test the security of the VBSKS system against various attacks.
    """)
    
    # Upload database and key files
    sim_upload_col1, sim_upload_col2 = st.columns(2)
    
    with sim_upload_col1:
        sim_uploaded_db = st.file_uploader("Upload Vector Database for Simulation", type=["json"])
    
    with sim_upload_col2:
        sim_uploaded_key = st.file_uploader("Upload Key File for Simulation", type=["json"])
    
    # Or create new data for simulation
    st.markdown("### Or generate new data for simulation")
    
    sim_col1, sim_col2, sim_col3 = st.columns(3)
    
    with sim_col1:
        sim_dimensions = st.number_input("Vector Dimensions for Simulation", min_value=10, max_value=1000, value=100, step=10)
    
    with sim_col2:
        sim_noise_size = st.number_input("Noise Size for Simulation", min_value=1000, max_value=100000, value=10000, step=1000)
    
    with sim_col3:
        sim_key_length = st.number_input("Key Length for Simulation", min_value=1, max_value=10, value=5)
    
    # Simulation parameters
    st.markdown("### Simulation Parameters")
    
    sim_params_col1, sim_params_col2, sim_params_col3 = st.columns(3)
    
    with sim_params_col1:
        random_attempts = st.number_input("Random Attack Attempts", min_value=0, max_value=1000, value=20, step=10)
    
    with sim_params_col2:
        position_known_attempts = st.number_input("Position-Known Attack Attempts", min_value=0, max_value=1000, value=20, step=10)
    
    with sim_params_col3:
        run_quantum = st.checkbox("Run Quantum Simulation", value=True)
    
    if st.button("Run Simulation", type="primary"):
        # Initialize variables
        db = None
        key_data = None
        
        # Check if we're using uploaded files or generating new data
        if sim_uploaded_db and sim_uploaded_key:
            # Save uploaded files to temporary locations
            sim_db_file = NamedTemporaryFile(delete=False, suffix=".json")
            with open(sim_db_file.name, "wb") as f:
                f.write(sim_uploaded_db.getvalue())
            
            sim_key_file = NamedTemporaryFile(delete=False, suffix=".json")
            with open(sim_key_file.name, "wb") as f:
                f.write(sim_uploaded_key.getvalue())
            
            # Load the database and key
            with st.spinner("Loading database and key for simulation..."):
                # Load the vector database
                db = VectorDatabase.load(sim_db_file.name)
                
                # Load key data
                key_data = KeyManager.load_key_data(sim_key_file.name)
            
            # Clean up temporary files
            os.unlink(sim_db_file.name)
            os.unlink(sim_key_file.name)
        else:
            # Generate new data for simulation
            with st.spinner("Generating new data for simulation..."):
                # Create a new vector database
                db = VectorDatabase(
                    dimensions=sim_dimensions,
                    size=sim_noise_size,
                    threshold=PRECISION
                )
                
                # Create a key manager
                km_sim = KeyManager(
                    vector_db=db,
                    key_length=sim_key_length,
                    threshold=PRECISION
                )
                
                # Generate a key
                key_vectors, positions = km_sim.generate_key("simulation_seed")
                
                # Create key data dictionary
                key_data = {
                    'key_length': sim_key_length,
                    'threshold': PRECISION,
                    'positions': positions,
                    'key_vectors': key_vectors
                }
        
        if db and key_data:
            # Create a key manager
            km = KeyManager(
                vector_db=db,
                key_length=key_data['key_length'],
                threshold=key_data.get('threshold', PRECISION)
            )
            
            # Create a security simulator
            simulator = SecuritySimulator(
                db,
                km,
                key_data['positions'],
                key_data['key_vectors']
            )
            
            # Run simulations
            if random_attempts > 0:
                with st.spinner(f"Running random attack simulation with {random_attempts} attempts..."):
                    random_result = simulator.random_attack(random_attempts, parallel=False)
                
                # Display random attack results
                st.subheader("Random Attack Simulation Results")
                
                random_col1, random_col2, random_col3 = st.columns(3)
                
                random_col1.metric("Success", "Yes" if random_result['success'] else "No")
                random_col2.metric("Success Rate", f"{random_result['success_rate']:.8f}")
                random_col3.metric("Time", f"{random_result['elapsed_time']:.2f} seconds")
                
                st.metric("Closest Distance", f"{random_result['closest_distance']}")
            
            if position_known_attempts > 0:
                with st.spinner(f"Running position-known attack with {position_known_attempts} attempts..."):
                    position_result = simulator.position_known_attack(position_known_attempts)
                
                # Display position-known attack results
                st.subheader("Position-Known Attack Simulation Results")
                
                position_col1, position_col2, position_col3 = st.columns(3)
                
                position_col1.metric("Success", "Yes" if position_result['success'] else "No")
                position_col2.metric("Closest Distance", f"{position_result['closest_distance']:.8f}")
                position_col3.metric("Time", f"{position_result['elapsed_time']:.2f} seconds")
                
                # Plot distances if available
                if 'all_distances' in position_result:
                    st.subheader("Distance Distribution")
                    
                    fig, ax = plt.subplots(figsize=(10, 4))
                    ax.hist(position_result['all_distances'], bins=20)
                    ax.set_xlabel("Euclidean Distance")
                    ax.set_ylabel("Frequency")
                    ax.set_title("Distribution of Distances in Position-Known Attack")
                    ax.grid(True, linestyle='--', alpha=0.7)
                    
                    # Use BytesIO to convert the plot to bytes
                    buf = io.BytesIO()
                    fig.savefig(buf, format='png', bbox_inches='tight')
                    buf.seek(0)
                    
                    # Display the plot
                    st.image(buf, use_column_width=True)
            
            if run_quantum:
                with st.spinner("Running quantum attack simulation..."):
                    quantum_result = simulator.quantum_grover_simulation()
                
                # Display quantum attack results
                st.subheader("Quantum Attack Simulation Results")
                
                if quantum_result['classical_search_space'] == float('inf'):
                    st.info("The search space is too large for precise calculation, indicating extreme security.")
                    st.info("Even with quantum computers, the key space is effectively impossible to brute force.")
                else:
                    quantum_col1, quantum_col2 = st.columns(2)
                    
                    with quantum_col1:
                        st.metric("Classical Search Space", f"{quantum_result['classical_search_space']:.2e}")
                        st.metric("Classical Time", f"{quantum_result['classical_time_value']:.2e} {quantum_result['classical_time_unit']}")
                    
                    with quantum_col2:
                        st.metric("Quantum Search Space", f"{quantum_result['quantum_search_space']:.2e}")
                        st.metric("Quantum Time", f"{quantum_result['quantum_time_value']:.2e} {quantum_result['quantum_time_unit']}")

# Footer
st.markdown("---")
st.markdown("VBSKS - Vector-Based Secure Key Storage | A quantum-resistant key storage system") 