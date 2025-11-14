import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Lock, Shield, AlertTriangle, CheckCircle, Skull, Send, Terminal, XCircle, Network } from 'lucide-react';
import { db, ref, push, onValue, set, remove } from './firebase';

// === [GIỮ NGUYÊN TẤT CẢ HÀM CRYPTO] ===
interface Message {
  senderId: string;
  mode: 'L1' | 'L2';
  ciphertext: string;
  iv: string;
  signature?: string;
  ephemeralPubKey?: JsonWebKey;
  createdAt: string;
}

const USER_ID = 'Alice';
const PEER_ID = 'Bob';

const AES_PARAMS = { name: 'AES-GCM', length: 256 } as const;
const ECDH_PARAMS = { name: 'ECDH', namedCurve: 'P-256' } as const;
const ECDSA_PARAMS = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;

const ab2b64 = (buffer: ArrayBuffer | Uint8Array): string => {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return btoa(String.fromCharCode(...bytes));
};

const b642ab = (base64: string): ArrayBuffer => {
  const binary = atob(base64);
  const array = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) array[i] = binary.charCodeAt(i);
  return array.buffer;
};

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

const generateEphemeral = () => crypto.subtle.generateKey(ECDH_PARAMS, true, ['deriveKey']);

const importLongTermPub = async (json: string) => {
  const { ecdh, ecdsa } = JSON.parse(json);
  const [ecdhKey, ecdsaKey] = await Promise.all([
    crypto.subtle.importKey('jwk', ecdh, ECDH_PARAMS, true, []),
    crypto.subtle.importKey('jwk', ecdsa, ECDSA_PARAMS, true, ['verify']),
  ]);
  return { ecdh: ecdhKey, ecdsa: ecdsaKey };
};

const importEphemeralPub = (jwk: JsonWebKey) =>
  crypto.subtle.importKey('jwk', jwk, ECDH_PARAMS, true, []);

const deriveSecret = (privateKey: CryptoKey, publicKey: CryptoKey) =>
  crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    AES_PARAMS,
    true,
    ['encrypt', 'decrypt']
  );

const encrypt = async (key: CryptoKey, text: string) => {
  const data = new TextEncoder().encode(text);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { ciphertext: ab2b64(ct), iv: ab2b64(iv) };
};

const decrypt = async (key: CryptoKey, ctB64: string, ivB64: string) => {
  const ct = b642ab(ctB64);
  const iv = b642ab(ivB64);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(pt);
};

const sign = (data: string, priv: CryptoKey) =>
  crypto.subtle.sign(ECDSA_PARAMS, priv, new TextEncoder().encode(data)).then(ab2b64);

const verify = async (data: string, sigB64: string, pub: CryptoKey) =>
  crypto.subtle.verify(ECDSA_PARAMS, pub, b642ab(sigB64), new TextEncoder().encode(data));

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
  const [bobOriginalPubKeyState, setBobOriginalPubKeyState] = useState('');
  const [isMITMAttack, setIsMITMAttack] = useState(false);
  const [hackerLogs, setHackerLogs] = useState<{ id: number, text: string, compromised: boolean }[]>([]);
  const [snapshotData, setSnapshotData] = useState<any>({}); // Lưu key Firebase để xóa

  const chatRef = useRef<HTMLDivElement>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const isAttacked = !!leakedKeys;

  // === TỐI ƯU CUỘN CHAT & LOG ===
  const scrollChat = useCallback(() => {
    requestAnimationFrame(() => {
      chatRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
    });
  }, []);

  const scrollLog = useCallback(() => {
    requestAnimationFrame(() => {
      logRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
    });
  }, []);

  useEffect(() => { scrollChat(); }, [messages, scrollChat]);
  useEffect(() => { scrollLog(); }, [hackerLogs, scrollLog]);

  // === KHỞI TẠO KHÓA ===
  useEffect(() => {
    (async () => {
      const alice = await generateLongTermKeys();
      const bob = await generateLongTermKeys();
      const mallory = await generateLongTermKeys();

      setMyKeys(alice);
      setPeerKeys(bob);
      setMalloryKeys(mallory);
      setBobOriginalPubKeyState(bob.longTermPublicKey);

      await set(ref(db, 'publicKeys'), {
        [USER_ID]: alice.longTermPublicKey,
        [PEER_ID]: bob.longTermPublicKey,
      });

      setReady(true);
    })();
  }, []);

  // === LẮNG NGHE TIN NHẮN + LƯU KEY ĐỂ XÓA ===
  useEffect(() => {
    const messagesRef = ref(db, 'messages');
    const unsubscribe = onValue(messagesRef, (snapshot) => {
      const data = snapshot.val() || {};
      setSnapshotData(data);
      const loadedMessages = Object.values(data) as Message[];
      setMessages(loadedMessages.sort((a, b) =>
        new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
      ));
    });
    return () => unsubscribe();
  }, []);

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
        if (!m.ephemeralPubKey || !m.signature) return '[LỖI] Thiếu chữ ký hoặc khóa tạm';
        const ephPub = await importEphemeralPub(m.ephemeralPubKey);
        key = await deriveSecret(peerKeys.ecdhKeyPair.privateKey!, ephPub);
        const ok = await verify(m.ciphertext, m.signature, senderPub.ecdsa);
        if (!ok) return '[CẢNH BÁO] CHỮ KÝ KHÔNG HỢP LỆ! (MITM)';
      }
      return await decrypt(key, m.ciphertext, m.iv);
    } catch (err) {
      console.error('Decrypt error:', err);
      return '[LỖI] Không thể giải mã';
    }
  };

  const decryptAttacker = async (m: Message, originalText: string): Promise<{ text: string, compromised: boolean }> => {
    if (isMITMAttack && m.mode === 'L1') {
      return { text: `[L1/MITM] Hacker đã chặn và giải mã: "${originalText}"`, compromised: true };
    }

    if (isMITMAttack && m.mode === 'L2') {
      return { text: `[L2/MITM] Chặn tin nhắn: ${m.ciphertext.slice(0, 10)}... (Chữ ký từ chối)`, compromised: false };
    }

    if (!leakedKeys) return { text: `[${m.mode}] Chặn tin nhắn: ${m.ciphertext.slice(0, 10)}...`, compromised: false };

    if (m.mode === 'L2') {
      return { text: `[L2 - PFS] Tin nhắn "${originalText.slice(0, 15)}..." BÍ MẬT HOÀN TOÀN!`, compromised: false };
    }

    try {
      const bobPub = await importLongTermPub(bobOriginalPubKeyState);
      const sharedKey = await deriveSecret(leakedKeys.ecdhKeyPair.privateKey!, bobPub.ecdh);
      const plaintext = await decrypt(sharedKey, m.ciphertext, m.iv);
      return { text: `[L1] KHÓA LỘ! ĐÃ ĐỌC: "${plaintext}"`, compromised: true };
    } catch {
      return { text: `[L1] Giải mã thất bại`, compromised: false };
    }
  };

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
        signature = await sign(currentText, myKeys.ecdsaKeyPair.privateKey!);
      }

      const { ciphertext, iv } = await encrypt(sharedKey, currentText);

      const msg: any = {
        senderId: USER_ID,
        mode,
        ciphertext,
        iv,
        createdAt: new Date().toISOString(),
      };

      if (mode === 'L2') {
        msg.signature = signature;
        msg.ephemeralPubKey = ephPubJwk;
      }

      await push(ref(db, 'messages'), msg);

      const logResult = await decryptAttacker(msg as Message, currentText);
      setHackerLogs(prev => [...prev, { id: Date.now(), ...logResult }]);

      setText('');
    } catch (err: any) {
      console.error('Lỗi gửi tin:', err);
      setHackerLogs(prev => [...prev, { id: Date.now(), text: '[LỖI] Gửi tin thất bại!', compromised: true }]);
    }
  };

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
  };

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
      await set(ref(db, `publicKeys/${PEER_ID}`), bobOriginalPubKeyState);
      setHackerLogs(prev => [...prev, {
        id: Date.now(),
        text: '[MITM TẮT] Khôi phục khóa gốc của Bob.',
        compromised: false
      }]);
    }
  };

  // === XÓA TIN NHẮN ===
  const deleteMessage = async (index: number) => {
    const keys = Object.keys(snapshotData);
    const keyToDelete = keys[index];
    if (!keyToDelete) return;

    await remove(ref(db, `messages/${keyToDelete}`));

    setHackerLogs(prev => [...prev, {
      id: Date.now(),
      text: `[XÓA] Tin nhắn đã bị xóa khỏi Firebase`,
      compromised: false
    }]);
  };

  const deleteAllMessages = async () => {
    if (!confirm('Xóa toàn bộ tin nhắn?')) return;
    await remove(ref(db, 'messages'));
    setHackerLogs(prev => [...prev, {
      id: Date.now(),
      text: '[XÓA HẾT] Toàn bộ tin nhắn đã bị xóa!',
      compromised: false
    }]);
  };

  // === MESSAGE BOX – CÓ NÚT XÓA ===
  const MessageBox = React.memo(({ msg, index }: { msg: Message; index: number }) => {
    const [pt, setPt] = useState('Đang giải mã...');
    useEffect(() => { decryptUser(msg).then(setPt); }, [msg]);
    const isAlice = msg.senderId === USER_ID;
    const error = pt.includes('LỖI') || pt.includes('CẢNH BÁO');

    return (
      <div className={`flex ${isAlice ? 'justify-end' : 'justify-start'} mb-2 group`}>
        <div className={`
          relative max-w-[60%] w-fit px-3 py-2.5 rounded-xl shadow-md border break-all text-sm
          ${isAlice ? 'bg-cyan-900/80 border-cyan-700' : 'bg-slate-800/90 border-slate-700'}
          ${error ? 'ring-2 ring-red-500' : ''}
        `}>
          {error && <Skull className="absolute -top-2 -right-2 w-5 h-5 text-red-400 animate-pulse" />}
          <p className="text-xs font-light text-slate-400 mb-0.5">{isAlice ? USER_ID : PEER_ID}</p>
          <p className="font-medium whitespace-pre-wrap break-all leading-snug">
            {error ? <XCircle className="inline w-4 h-4 mr-1.5 text-red-500"/> : ''}
            {pt}
          </p>
          <div className="flex items-center justify-between mt-1.5 pt-1.5 border-t border-white/10 text-xs opacity-70">
            <span className={`px-2 py-0.5 rounded-full font-bold text-xs ${
              msg.mode === 'L2' ? 'bg-yellow-500 text-black' : 'bg-blue-600 text-blue-100'
            }`}>
              {msg.mode === 'L2' ? 'L2 - PFS' : 'L1'}
            </span>
            <span className='text-slate-400'>
              {new Date(msg.createdAt).toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })}
            </span>
          </div>

          {/* NÚT XÓA – CHỈ HIỆN KHI HOVER & LÀ ALICE */}
          {isAlice && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                deleteMessage(index);
              }}
              className="absolute -top-2 -left-2 opacity-0 group-hover:opacity-100 transition-opacity bg-red-600 hover:bg-red-700 rounded-full p-1 shadow-lg"
            >
              <XCircle className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>
    );
  });

  const HackerLog = React.memo(({ log }: { log: { id: number, text: string, compromised: boolean } }) => {
    return (
      <div className={`font-mono text-xs py-1 border-b border-slate-700/50 ${log.compromised ? 'text-red-400 bg-red-950/20' : 'text-emerald-400'}`}>
        {log.compromised ? <Skull className="inline w-3 h-3 mr-2 animate-pulse"/> : <Shield className="inline w-3 h-3 mr-2"/>}
        {log.text}
      </div>
    );
  });

  // === LAYOUT MỚI: CHAT TRÁI + HACKER LOG PHẢI + XÓA TIN ===
  return (
    <div className="flex h-screen bg-slate-950 text-white">
      {/* === CHAT – BÊN TRÁI (70%) === */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* HEADER */}
        <header className="flex-shrink-0 bg-gradient-to-r from-slate-900 to-slate-800 border-b border-slate-700 px-4 py-3 shadow-xl z-10">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="relative">
                <Shield className="w-8 h-8 text-cyan-400" />
                <div className="absolute inset-0 blur-xl bg-cyan-400/30 rounded-full"></div>
              </div>
              <div>
                <h1 className="text-lg font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                  E2EE + PFS Demo
                </h1>
                <div className='flex items-center gap-3'>
                  <p className="text-xs text-slate-400">Firebase RTDB</p>
                  <span className="flex items-center gap-1 text-green-400 font-medium text-xs">
                    <CheckCircle className="w-3.5 h-3.5" /> An toàn
                  </span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={simulateMITMAttack} className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${isMITMAttack ? 'bg-orange-600 shadow-orange-600/50' : 'bg-slate-700 hover:bg-slate-600'}`}>
                <Network className='inline w-3.5 h-3.5 mr-1'/> {isMITMAttack ? 'MITM ON' : 'MITM'}
              </button>
              <button onClick={simulateLeakAttack} disabled={isAttacked || isMITMAttack} className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${isAttacked ? 'bg-red-600 shadow-red-600/50 cursor-not-allowed' : 'bg-slate-700 hover:bg-slate-600'}`}>
                <AlertTriangle className='inline w-3.5 h-3.5 mr-1'/> {isAttacked ? 'LỘ' : 'LEAK'}
              </button>
            </div>
          </div>
        </header>

        {/* CHỌN CHẾ ĐỘ + NÚT XÓA HẾT */}
        <div className="flex-shrink-0 bg-slate-900/80 backdrop-blur-sm border-b border-slate-700 px-4 py-3 z-10 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 font-medium text-sm">Chế độ:</span>
            <button onClick={() => setMode('L1')} className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${mode === 'L1' ? 'bg-blue-600 shadow-blue-600/50' : 'bg-slate-700 hover:bg-slate-600'}`}>
              L1
            </button>
            <button onClick={() => setMode('L2')} className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${mode === 'L2' ? 'bg-gradient-to-r from-yellow-500 to-amber-500 text-black shadow-yellow-500/50' : 'bg-slate-700 hover:bg-slate-600'}`}>
              L2 - PFS
            </button>
          </div>
          {messages.length > 0 && (
            <button
              onClick={deleteAllMessages}
              className="text-xs px-2 py-1 bg-red-900/70 hover:bg-red-800 rounded-lg font-medium transition-all flex items-center gap-1"
            >
              <XCircle className="w-3.5 h-3.5" /> Xóa hết
            </button>
          )}
        </div>

        {/* CHAT CONTENT */}
        <div className="flex-1 overflow-y-auto px-3 py-3 pb-40 scrollbar-thin">
          {messages.length === 0 ? (
            <div className="text-center py-12">
              <Lock className="w-12 h-12 mx-auto mb-4 text-slate-600" />
              <p className="text-sm text-slate-500 font-medium">Gửi tin nhắn để thấy PFS</p>
              <p className="text-xs text-slate-600 mt-1">Dữ liệu lưu trên Firebase</p>
            </div>
          ) : (
            <div className="space-y-3">
              {messages.map((m, i) => (
                <MessageBox key={i} msg={m} index={i} />
              ))}
            </div>
          )}
          <div ref={chatRef} />
        </div>

        {/* INPUT */}
        <div className="fixed inset-x-0 bottom-0 bg-slate-900/95 backdrop-blur-xl border-t border-slate-700 px-2 py-2.5 shadow-2xl z-50">
          <form onSubmit={send} className="flex gap-1.5 items-center max-w-full">
            <input
              value={text}
              onChange={e => setText(e.target.value)}
              placeholder={`Tin nhắn ${mode}...`}
              disabled={!ready}
              className="flex-1 min-w-0 px-3 py-2 bg-slate-800/80 border border-slate-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500 text-white placeholder-slate-400 text-xs"
            />
            <button
              type="submit"
              disabled={!ready || !text.trim()}
              className="px-3 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 rounded-lg font-bold text-xs flex items-center gap-1 transition-all shadow-md shadow-cyan-600/50 disabled:opacity-50 whitespace-nowrap"
            >
              <Send className="w-3.5 h-3.5" /> Gửi
            </button>
          </form>
        </div>
      </div>

      {/* === HACKER LOG – BÊN PHẢI (30%) === */}
      <div className="w-80 flex flex-col bg-slate-900/90 border-l border-slate-700 z-10">
        <div className="flex-shrink-0 p-4 border-b border-slate-700">
          <h2 className="text-sm font-bold text-orange-400 flex items-center gap-1.5">
            <Terminal className="w-4 h-4" /> Hacker Log
          </h2>
        </div>
        <div className="flex-1 overflow-y-auto p-3 scrollbar-thin" ref={logRef}>
          {hackerLogs.length === 0 ? (
            <p className="text-slate-500 font-mono text-xs">... Chờ tấn công</p>
          ) : (
            hackerLogs.map(log => <HackerLog key={log.id} log={log} />)
          )}
        </div>
      </div>
    </div>
  );
};

export default ChatAppE2EE;