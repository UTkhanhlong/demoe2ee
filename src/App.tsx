import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Lock, Shield, AlertTriangle, CheckCircle, Skull, Send, Terminal, XCircle, Network } from 'lucide-react';
import { db, ref, push, onValue, set } from './firebase'; 

// Khai báo kiểu dữ liệu cho tin nhắn
interface Message {
  senderId: string;
  mode: 'L1' | 'L2';
  ciphertext: string;
  iv: string;
  signature?: string;
  ephemeralPubKey?: JsonWebKey;
  createdAt: string;
}

// XÓA: let messageDatabase: Message[] = [];
// XÓA: const publicKeysDatabase: Record<string, { pubKey: string }> = {};
let bobOriginalPubKey = ''; // Giữ lại để khôi phục khi tắt MITM

const USER_ID = 'Alice';
const PEER_ID = 'Bob';

// Cấu hình thuật toán mật mã
const AES_PARAMS = { name: 'AES-GCM', length: 256 } as const;
const ECDH_PARAMS = { name: 'ECDH', namedCurve: 'P-256' } as const;
const ECDSA_PARAMS = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;

// Helper: Chuyển ArrayBuffer sang Base64
const ab2b64 = (buffer: ArrayBuffer | Uint8Array): string => {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return btoa(String.fromCharCode(...bytes));
};

// Helper: Chuyển Base64 sang ArrayBuffer
const b642ab = (base64: string): ArrayBuffer => {
  const binary = atob(base64);
  const array = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) array[i] = binary.charCodeAt(i);
  return array.buffer;
};

// 1. Tạo cặp khóa dài hạn
const generateLongTermKeys = async () => {
  const ecdh = await crypto.subtle.generateKey(ECDH_PARAMS, true, ['deriveKey']);
  const ecdsa = await crypto.subtle.generateKey(ECDSA_PARAMS, true, ['sign', 'verify']);
  const [ecdhPub, ecdsaPub] = await Promise.all([
    crypto.subtle.exportKey('jwk', ecdh.publicKey!),
    crypto.subtle.exportKey('jwk', ecdsa.publicKey!),
  ]);
  return {
    ecdhKeyPair: ecdh,
    ecdsaKeyPair: ecdsa,
    longTermPublicKey: JSON.stringify({ ecdh: ecdhPub, ecdsa: ecdsaPub }),
  };
};

// 2. Tạo khóa tạm thời (PFS)
const generateEphemeral = () => crypto.subtle.generateKey(ECDH_PARAMS, true, ['deriveKey']);

// 3. Import Public Key dài hạn
const importLongTermPub = async (json: string) => {
  const { ecdh, ecdsa } = JSON.parse(json);
  const [ecdhKey, ecdsaKey] = await Promise.all([
    crypto.subtle.importKey('jwk', ecdh, ECDH_PARAMS, true, []),
    crypto.subtle.importKey('jwk', ecdsa, ECDSA_PARAMS, true, ['verify']),
  ]);
  return { ecdh: ecdhKey, ecdsa: ecdsaKey };
};

// 4. Import Ephemeral Key
const importEphemeralPub = (jwk: JsonWebKey) =>
  crypto.subtle.importKey('jwk', jwk, ECDH_PARAMS, true, []);

// 5. Derive Shared Secret
const deriveSecret = (privateKey: CryptoKey, publicKey: CryptoKey) =>
  crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    AES_PARAMS,
    true,
    ['encrypt', 'decrypt']
  );

// 6. Mã hóa
const encrypt = async (key: CryptoKey, text: string) => {
  const data = new TextEncoder().encode(text);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { ciphertext: ab2b64(ct), iv: ab2b64(iv) };
};

// 7. Giải mã
const decrypt = async (key: CryptoKey, ctB64: string, ivB64: string) => {
  const ct = b642ab(ctB64);
  const iv = b642ab(ivB64);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(pt);
};

// 8. Ký số
const sign = (data: string, priv: CryptoKey) =>
  crypto.subtle.sign(ECDSA_PARAMS, priv, new TextEncoder().encode(data)).then(ab2b64);

// 9. Xác minh chữ ký
const verify = async (data: string, sigB64: string, pub: CryptoKey) =>
  crypto.subtle.verify(ECDSA_PARAMS, pub, b642ab(sigB64), new TextEncoder().encode(data));

// LẤY PUBLIC KEY TỪ FIREBASE
const getPeerPublicKey = async (id: string): Promise<string | null> => {
  return new Promise((resolve) => {
    const keyRef = ref(db, `publicKeys/${id}`);
    const unsubscribe = onValue(keyRef, (snapshot) => {
      resolve(snapshot.val());
      unsubscribe();
    }, { onlyOnce: true });
  });
};

const ChatAppE2EE: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [text, setText] = useState('');
  const [mode, setMode] = useState<'L1' | 'L2'>('L2');
  const [ready, setReady] = useState(false);
  const [myKeys, setMyKeys] = useState<any>(null);
  const [peerKeys, setPeerKeys] = useState<any>(null);
  const [leakedKeys, setLeakedKeys] = useState<any>(null);
  const [malloryKeys, setMalloryKeys] = useState<any>(null);
  const [isMITMAttack, setIsMITMAttack] = useState(false);
  const [hackerLogs, setHackerLogs] = useState<{ id: number, text: string, compromised: boolean }[]>([]);
  const chatRef = useRef<HTMLDivElement>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const isAttacked = !!leakedKeys;

  const scrollChat = useCallback(() => {
    chatRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, []);

  const scrollLog = useCallback(() => {
    logRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, []);

  // KHỞI TẠO KHÓA + LƯU LÊN FIREBASE
  useEffect(() => {
    (async () => {
      const alice = await generateLongTermKeys();
      const bob = await generateLongTermKeys();
      const mallory = await generateLongTermKeys();

      setMyKeys(alice);
      setPeerKeys(bob);
      setMalloryKeys(mallory);

      bobOriginalPubKey = bob.longTermPublicKey;

      // LƯU PUBLIC KEY LÊN FIREBASE
      await set(ref(db, 'publicKeys'), {
        [USER_ID]: alice.longTermPublicKey,
        [PEER_ID]: bob.longTermPublicKey,
      });

      setReady(true);
    })();
  }, []);

  // LẮNG NGHE TIN NHẮN TỪ FIREBASE
  useEffect(() => {
    const messagesRef = ref(db, 'messages');
    const unsubscribe = onValue(messagesRef, (snapshot) => {
      const data = snapshot.val();
      if (data) {
        const loadedMessages = Object.values(data) as Message[];
        setMessages(loadedMessages.sort((a, b) =>
          new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
        ));
      } else {
        setMessages([]);
      }
      scrollChat();
    });

    return () => unsubscribe();
  }, [scrollChat]);

  // Giải mã cho người dùng (Bob)
  const decryptUser = async (m: Message): Promise<string> => {
    if (isMITMAttack && m.mode === 'L1') {
      return '[LỖI MÃ HÓA] Không thể giải mã (MITM: Khóa bị giả mạo)';
    }

    if (!peerKeys) return 'Đang tải khóa...';
    const senderPubKey = await getPeerPublicKey(m.senderId);
    if (!senderPubKey) return '[LỖI] Không tìm thấy khóa người gửi';
    const senderPub = await importLongTermPub(senderPubKey);

    try {
      let key: CryptoKey;
      if (m.mode === 'L1') {
        key = await deriveSecret(peerKeys.ecdhKeyPair.privateKey!, senderPub.ecdh);
      } else {
        const ephPub = await importEphemeralPub(m.ephemeralPubKey!);
        key = await deriveSecret(peerKeys.ecdhKeyPair.privateKey!, ephPub);
        const ok = await verify(m.ciphertext, m.signature!, senderPub.ecdsa);
        if (!ok) return '[CẢNH BÁO] CHỮ KÝ KHÔNG HỢP LỆ! (MITM)';
      }
      return await decrypt(key, m.ciphertext, m.iv);
    } catch {
      return '[LỖI] Không thể giải mã';
    }
  };

  // Giải mã cho Hacker
  const decryptAttacker = async (m: Message, originalText: string): Promise<{ text: string, compromised: boolean }> => {
    if (isMITMAttack) {
      if (m.mode === 'L1') {
        return { text: `[L1/MITM] Hacker đã chặn và giải mã: "${originalText}"`, compromised: true };
      } else {
        return { text: `[L2/MITM] Chặn tin nhắn: ${m.ciphertext.slice(0, 10)}... (Chữ ký từ chối)`, compromised: false };
      }
    }

    if (!leakedKeys) return { text: `[${m.mode}] Chặn tin nhắn: ${m.ciphertext.slice(0, 10)}...`, compromised: false };

    const attackerPriv = leakedKeys.ecdhKeyPair.privateKey!;
    const bobPubKey = bobOriginalPubKey || (await getPeerPublicKey(PEER_ID));
    if (!bobPubKey) return { text: '[LỖI] Không có khóa Bob', compromised: false };
    const bobPub = await importLongTermPub(bobPubKey);

    if (m.mode === 'L2') {
      return { text: `[L2 - PFS] Tin nhắn "${originalText.slice(0, 15)}..." BÍ MẬT HOÀN TOÀN!`, compromised: false };
    }

    try {
      const sharedKey = await deriveSecret(attackerPriv, bobPub.ecdh);
      const plaintext = await decrypt(sharedKey, m.ciphertext, m.iv);
      return { text: `[L1] KHÓA LỘ! ĐÃ ĐỌC: "${plaintext}"`, compromised: true };
    } catch {
      return { text: `[L1] Giải mã thất bại`, compromised: false };
    }
  };

  // GỬI TIN NHẮN LÊN FIREBASE
  const send = async (e: React.FormEvent) => {
    e.preventDefault();
    const currentText = text.trim();
    if (!currentText || !ready || !myKeys) return;

    const peerPubKey = await getPeerPublicKey(PEER_ID);
    if (!peerPubKey) return;
    const peerPub = await importLongTermPub(peerPubKey);

    let sharedKey: CryptoKey;
    let ephPubJwk: JsonWebKey | undefined;
    let signature: string | undefined;

    try {
      if (mode === 'L1') {
        sharedKey = await deriveSecret(myKeys.ecdhKeyPair.privateKey!, peerPub.ecdh);
      } else {
        const ephemeral = await generateEphemeral();
        ephPubJwk = await crypto.subtle.exportKey('jwk', ephemeral.publicKey!);
        sharedKey = await deriveSecret(ephemeral.privateKey!, peerPub.ecdh);
      }

      const { ciphertext, iv } = await encrypt(sharedKey, currentText);
      if (mode === 'L2') {
        signature = await sign(ciphertext, myKeys.ecdsaKeyPair.privateKey!);
      }

      const msg: Message = {
        senderId: USER_ID,
        mode,
        ciphertext,
        iv,
        signature,
        ephemeralPubKey: ephPubJwk,
        createdAt: new Date().toISOString(),
      };

      // GỬI LÊN FIREBASE
      await push(ref(db, 'messages'), msg);

      // Cập nhật log hacker
      const logResult = await decryptAttacker(msg, currentText);
      setHackerLogs(prev => [...prev, { id: Date.now(), ...logResult }]);

      setText('');
    } catch (err: any) {
      console.error(`Lỗi gửi tin: ${err.message}`);
    }
  };

  // Tấn công Key Leak
  const simulateLeakAttack = async () => {
    if (!myKeys || isAttacked) return;
    setLeakedKeys(myKeys);

    setHackerLogs(prev => [...prev, {
      id: Date.now(),
      text: '[CẢNH BÁO] KHÓA DÀI HẠN CỦA ALICE BỊ RÒ RỈ!',
      compromised: true
    }]);

    for (const m of messages) {
      const originalText = await decryptUser(m).catch(() => 'Lỗi');
      const logResult = await decryptAttacker(m, originalText);
      setHackerLogs(prev => [...prev, { id: Date.now() + Math.random(), ...logResult }]);
    }
    setTimeout(scrollLog, 200);
  };

  // Tấn công MITM
  const simulateMITMAttack = async () => {
    if (!malloryKeys) return;
    const currentMITMState = !isMITMAttack;
    setIsMITMAttack(currentMITMState);

    if (currentMITMState) {
      await set(ref(db, `publicKeys/${PEER_ID}`), malloryKeys.longTermPublicKey);
      setHackerLogs(prev => [...prev, {
        id: Date.now(),
        text: '[MITM BẬT] Mallory đã thay thế khóa của Bob!',
        compromised: true
      }]);
    } else {
      await set(ref(db, `publicKeys/${PEER_ID}`), bobOriginalPubKey);
      setHackerLogs(prev => [...prev, {
        id: Date.now(),
        text: '[MITM TẮT] Khôi phục khóa gốc của Bob.',
        compromised: false
      }]);
    }
    setTimeout(scrollLog, 100);
  };

  // Component hiển thị tin nhắn
  const MessageBox = React.memo(({ msg }: { msg: Message }) => {
    const [pt, setPt] = useState('Đang giải mã...');
    useEffect(() => { decryptUser(msg).then(setPt); }, [msg]);
    const isAlice = msg.senderId === USER_ID;
    const error = pt.includes('LỖI') || pt.includes('CẢNH BÁO');

    return (
      <div className={`flex mb-5 ${isAlice ? 'justify-end' : 'justify-start'}`}>
        <div className={`relative max-w-lg px-5 py-4 rounded-2xl shadow-xl border
          ${isAlice ? 'bg-cyan-900/80 border-cyan-700' : 'bg-slate-800/90 border-slate-700'}
          ${error ? 'ring-2 ring-red-500' : ''}`}>
          {error && <Skull className="absolute -top-3 -right-3 w-8 h-8 text-red-400 animate-pulse" />}
          <p className="text-sm font-light text-slate-400 mb-1">{isAlice ? USER_ID : PEER_ID}</p>
          <p className="text-base font-medium whitespace-pre-wrap break-words leading-relaxed">
            {error ? <XCircle className="inline w-5 h-5 mr-2 text-red-500"/> : ''}
            {pt}
          </p>
          <div className="flex items-center justify-between mt-3 pt-3 border-t border-white/10 text-xs opacity-75">
            <span className={`px-3 py-1 rounded-full font-semibold text-xs ${msg.mode === 'L2' ? 'bg-yellow-500 text-black' : 'bg-blue-600 text-blue-100'}`}>
              {msg.mode === 'L2' ? 'L2 - PFS + Ký số' : 'L1 - Khóa dài hạn'}
            </span>
            <span className='text-slate-400'>
              {new Date(msg.createdAt).toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
            </span>
          </div>
        </div>
      </div>
    );
  });

  const HackerLog = React.memo(({ log }: { log: { id: number, text: string, compromised: boolean } }) => {
    return (
      <div key={log.id} className={`font-mono text-xs py-1 border-b border-slate-700/50 
        ${log.compromised ? 'text-red-400 bg-red-950/20' : 'text-emerald-400'}`}>
        {log.compromised ? <Skull className="inline w-3 h-3 mr-2 animate-pulse"/> : <Shield className="inline w-3 h-3 mr-2"/>}
        {log.text}
      </div>
    );
  });

  return (
    <div className="flex flex-col h-screen font-sans bg-slate-950 text-white">
      <header className="bg-gradient-to-r from-slate-900 to-slate-800 border-b border-slate-700 px-6 py-4 shadow-2xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="relative">
              <Shield className="w-10 h-10 text-cyan-400" />
              <div className="absolute inset-0 blur-xl bg-cyan-400/30 rounded-full"></div>
            </div>
            <div>
              <h1 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                E2EE + PFS Demo (Firebase)
              </h1>
              <div className='flex items-center gap-4'>
                <p className="text-sm text-slate-400">Real-time Database + Hosting</p>
                <span className="flex items-center gap-2 text-green-400 font-medium text-sm">
                  <CheckCircle className="w-4 h-4" /> Kết nối an toàn
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={simulateMITMAttack} className={`px-4 py-2 rounded-xl text-sm font-bold transition-all ${isMITMAttack ? 'bg-orange-600 shadow-lg shadow-orange-600/50' : 'bg-slate-700 hover:bg-slate-600'}`}>
              <Network className='inline w-4 h-4 mr-1'/> {isMITMAttack ? 'MITM ON' : 'MITM'}
            </button>
            <button onClick={simulateLeakAttack} disabled={isAttacked || isMITMAttack} className={`px-4 py-2 rounded-xl text-sm font-bold transition-all ${isAttacked ? 'bg-red-600 shadow-lg shadow-red-600/50 cursor-not-allowed' : 'bg-slate-700 hover:bg-slate-600'}`}>
              <AlertTriangle className='inline w-4 h-4 mr-1'/> {isAttacked ? 'KHÓA LỘ' : 'KEY LEAK'}
            </button>
          </div>
        </div>
      </header>

      <div className="bg-slate-900/80 backdrop-blur-sm border-b border-slate-700 px-6 py-3">
        <h2 className="text-sm font-bold text-slate-300 flex items-center gap-2 mb-2">
          <Terminal className="w-4 h-4 text-orange-400"/> Hacker Log
        </h2>
        <div className="max-h-24 overflow-y-auto rounded-lg bg-slate-950 p-2 border border-slate-700" ref={logRef}>
          {hackerLogs.length === 0 ? (
            <p className="text-xs text-slate-500 font-mono">... Chờ tấn công</p>
          ) : (
            hackerLogs.map(log => <HackerLog key={log.id} log={log}/>)
          )}
        </div>
      </div>

      <div className="bg-slate-900/80 backdrop-blur-sm border-b border-slate-700 px-6 py-4">
        <div className="flex items-center gap-3">
          <span className="text-slate-400 font-medium">Chế độ:</span>
          <button onClick={() => setMode('L1')} className={`px-4 py-2 rounded-xl text-sm font-semibold transition-all ${mode === 'L1' ? 'bg-blue-600 shadow-lg shadow-blue-600/50' : 'bg-slate-700 hover:bg-slate-600'}`}>
            L1 - Long-term
          </button>
          <button onClick={() => setMode('L2')} className={`px-4 py-2 rounded-xl text-sm font-semibold transition-all ${mode === 'L2' ? 'bg-gradient-to-r from-yellow-500 to-amber-500 text-black shadow-lg shadow-yellow-500/50' : 'bg-slate-700 hover:bg-slate-600'}`}>
            L2 - PFS + Sign
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto scrollbar-thin px-6 py-6">
        {messages.length === 0 && (
          <div className="text-center py-16">
            <Lock className="w-16 h-16 mx-auto mb-6 text-slate-600" />
            <p className="text-lg text-slate-500 font-medium">Gửi tin nhắn để thấy PFS</p>
            <p className="text-sm text-slate-600 mt-2">Dữ liệu được lưu trên Firebase Realtime DB</p>
          </div>
        )}
        {messages.map((m, i) => <MessageBox key={i} msg={m} />)}
        <div className="h-6" ref={chatRef} />
      </div>

      <form onSubmit={send} className="bg-slate-900/90 backdrop-blur border-t border-slate-700 px-6 py-5">
        <div className="flex gap-4 items-center">
          <input
            value={text}
            onChange={e => setText(e.target.value)}
            placeholder={`Tin nhắn ${mode}...`}
            disabled={!ready}
            className="flex-1 px-4 py-3 bg-slate-800/80 border border-slate-700 rounded-xl focus:outline-none focus:ring-2 focus:ring-cyan-500 text-white placeholder-slate-400 text-sm"
          />
          <button
            type="submit"
            disabled={!ready || !text.trim()}
            className="px-6 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 rounded-xl font-bold text-sm flex items-center gap-2 transition-all shadow-lg shadow-cyan-600/50"
          >
            <Send className="w-5 h-5" /> Gửi
          </button>
        </div>
      </form>
    </div>
  );
};

export default ChatAppE2EE;