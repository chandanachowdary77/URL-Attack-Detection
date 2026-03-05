import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";
import { getAnalytics } from "firebase/analytics";

// Firebase config provided by the user
const firebaseConfig = {
  apiKey: "AIzaSyAzVLzotmSKDmVHcff_mZG_oHekRG-Yf5g",
  authDomain: "urlattacks.firebaseapp.com",
  projectId: "urlattacks",
  storageBucket: "urlattacks.firebasestorage.app",
  messagingSenderId: "958614580240",
  appId: "1:958614580240:web:805c72ff21310dcdeeee95",
  measurementId: "G-LLJ3ZS7CK0"
};

const app = initializeApp(firebaseConfig);

// Initialize analytics (only works in browser)
try {
  getAnalytics(app);
} catch (e) {
  // ignore if analytics not available
}

export const auth = getAuth(app);
export const db = getFirestore(app);
export default app;
