// src/firebase.ts
import { initializeApp } from 'firebase/app';
import { getDatabase, ref, push, onValue, set } from 'firebase/database';

const firebaseConfig = {
  apiKey: "AIzaSyDobRSKCVCUJHmoatbYM5TB3MDQ2llO7ak",
  authDomain: "e2ee-e3a88.firebaseapp.com",
  databaseURL: "https://e2ee-e3a88-default-rtdb.asia-southeast1.firebasedatabase.app",
  projectId: "e2ee-e3a88",
  storageBucket: "e2ee-e3a88.firebasestorage.app",
  messagingSenderId: "926185670313",
  appId: "1:926185670313:web:7a9404cf939d6125998bb8"
};

const app = initializeApp(firebaseConfig);
const db = getDatabase(app);

export { db, ref, push, onValue, set };