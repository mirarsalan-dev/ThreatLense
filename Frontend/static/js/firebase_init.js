import { initializeApp } from "https://www.gstatic.com/firebasejs/10.10.0/firebase-app.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/10.10.0/firebase-auth.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/10.10.0/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyCNiNRdWRVS2SjP9DZwhpjgyeMwja5Prw4",
  authDomain: "aiml-mini-project-fa279.firebaseapp.com",
  projectId: "aiml-mini-project-fa279",
  storageBucket: "aiml-mini-project-fa279.firebasestorage.app",
  messagingSenderId: "37082340299",
  appId: "1:37082340299:web:7c5526b6cd573f73c6344e",
  measurementId: "G-DN89M376DW"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

export { auth, db };
