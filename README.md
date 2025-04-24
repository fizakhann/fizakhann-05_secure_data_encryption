Secure Data Encryption System using Streamlit
This is a simple Streamlit-based web application that allows users to securely store and retrieve their personal data using encryption and hashed passkeys. All operations are performed in-memory without using any external database.

Features
Encrypt and store data securely using Fernet (symmetric encryption).

User passkeys are hashed with SHA-256 for added security.

No external storage; all data is handled in memory.

Maximum of 3 failed attempts allowed before requiring reauthorization.

Reauthorization through a master password page.

Clean and user-friendly interface built with Streamlit.
