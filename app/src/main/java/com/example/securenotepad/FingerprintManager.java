package com.example.securenotepad;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Handler;
import android.provider.Settings;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Executor;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@RequiresApi(api = Build.VERSION_CODES.R)
public class FingerprintManager{

    private final static String notesKey = "notes";
    private final static String ivBytesKey = "ivBytes";
    private final static String notesName = "com.example.securenotepad";
    private final static String keyStoreType = "AndroidKeyStore";
    private final static String keyStoreAlias = "NoteApp";
    private Executor executor;
    private BiometricPrompt.PromptInfo promptInfo;
    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.AuthenticationCallback authenticationCallback;
    private AppCompatActivity activity;
    private boolean isEncrypt;
    private boolean isBiometric;
    private Runnable cipherNotesRunnable;
    public static Boolean exitApp;

    private static FingerprintManager fingerPrintInstance;

    public static FingerprintManager getInstance(AppCompatActivity activity) {
        if(null == fingerPrintInstance) {
            fingerPrintInstance = new FingerprintManager(activity);
        }
        return fingerPrintInstance;
    }

    private FingerprintManager(AppCompatActivity activity) {
        cipherNotesRunnable = null;
        exitApp = false;
        isBiometric = false;
        this.activity = activity;
        executor = ContextCompat.getMainExecutor(activity);
        authenticationCallback = new BiometricPrompt.AuthenticationCallback() {
            @RequiresApi(api = Build.VERSION_CODES.R)
            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(activity.getApplicationContext(),
                        "Authentication error: " + errString, Toast.LENGTH_SHORT)
                        .show();
                if(10 == errorCode) {
                    activity.finish();
                    System.exit(0);
                }
            }

            @Override
            public void onAuthenticationSucceeded(
                    @NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                Toast.makeText(activity, "Authentication succeeded!", Toast.LENGTH_SHORT).show();
                if(null != result.getCryptoObject()) {
                    Cipher cipher = result.getCryptoObject().getCipher();
                    onAuthenticationSucceededLocal(cipher);
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Toast.makeText(activity.getApplicationContext(), "Authentication failed",
                        Toast.LENGTH_SHORT)
                        .show();
            }
        };
        biometricPrompt = new BiometricPrompt(activity, executor, authenticationCallback);
        promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Biometric login for SecureNotepad")
                .setSubtitle("Log in using your biometric credential")
                //instead setAllowedAuthenticators
                .setNegativeButtonText("Close")
                .setConfirmationRequired(true)
                .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build();
    }

    public void onAuthenticationSucceededLocal(Cipher cipher) {
        if (null != cipher) {
            if (isEncrypt) {
                saveNotes(MainActivity.notes, cipher);
                if(exitApp) {
                    exitApp = false;
                    activity.finish();
                }
            } else {
                MainActivity.notes.clear();
                MainActivity.notes.addAll(loadNotes(cipher));
                MainActivity.arrayAdapter.notifyDataSetChanged();
            }
        }
    }

    public void saveNotes(List<String> notes, Cipher cipher) {
        try {
            List<String> notesList = new ArrayList<String>();
            if (null != notes)
                notesList.addAll(notes);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream outputStream = new ObjectOutputStream(byteArrayOutputStream);

            outputStream.writeObject(notesList);
            outputStream.flush();
            outputStream.close();
            byteArrayOutputStream.flush();
            byteArrayOutputStream.close();
            byte[] byteArrayNotes = byteArrayOutputStream.toByteArray();
            SharedPreferences sharedPreferencesNotes = activity.getApplicationContext().getSharedPreferences(notesName, Context.MODE_PRIVATE);
            sharedPreferencesNotes.edit().putString(notesKey, CryptoTools.encryptBytes(byteArrayNotes, cipher)).apply();
            IvParameterSpec ivParams = cipher.getParameters().getParameterSpec(IvParameterSpec.class);
            saveIV(ivParams.getIV());
        } catch (IOException | InvalidParameterSpecException e) {
            e.printStackTrace();
        }
    }

    public List<String> loadNotes(Cipher cipher) {
        SharedPreferences sharedPreferencesNotes = activity.getApplicationContext().getSharedPreferences(notesName, Context.MODE_PRIVATE);
        List<String> notesList = new ArrayList<String>();
        String notesString = sharedPreferencesNotes.getString(notesKey, null);
        if(null != notesString) {
            byte[] byteArrayNotes = CryptoTools.decryptBytes(notesString, cipher);
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayNotes);
            ObjectInputStream inputStream = null;
            try {
                inputStream = new ObjectInputStream(byteArrayInputStream);
                notesList = (List<String>) inputStream.readObject();
                inputStream.close();
                byteArrayInputStream.close();
            } catch (ClassNotFoundException | IOException e) {
                e.printStackTrace();
            }
        }
        return notesList;
    }

    private void saveIV(byte[] IVBytes) {
        String encryptedBase64IVText = Base64.getEncoder().encodeToString(IVBytes);
        SharedPreferences sharedPreferences = activity.getApplicationContext().getSharedPreferences(notesName, Context.MODE_PRIVATE);
        //if(null == sharedPreferences.getString(ivBytesKey, null)) sharedPreferences.edit().putString(ivBytesKey, encryptedBase64IVText).apply();
        sharedPreferences.edit().putString(ivBytesKey, encryptedBase64IVText).apply();
    }

    private byte[] loadIV(int blockSize) {
        SharedPreferences sharedPreferences = activity.getApplicationContext().getSharedPreferences(notesName, Context.MODE_PRIVATE);
        String encryptedBase64IVText = sharedPreferences.getString(ivBytesKey, null);
        byte[] IVBytes = null;
        if(null != encryptedBase64IVText) {
            IVBytes = Base64.getDecoder().decode(encryptedBase64IVText);
        } else {
            SecureRandom rnd = new SecureRandom();
            IVBytes = new byte[blockSize];
            rnd.nextBytes(IVBytes);
        }
        return IVBytes;
    }

    public void cipherNotes(boolean isEncrypt) {
        if(null == cipherNotesRunnable) {
            this.isEncrypt = isEncrypt;
            cipherNotesRunnable = new Runnable() {
                @Override
                public void run() {
                    AlertDialog.Builder builder = new AlertDialog.Builder(activity);
                    builder.setTitle("Authentication");
                    builder.setMessage("How do you want to authenticate?");

                    builder.setPositiveButton("Finger", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            isBiometric = true;
                            cipherNotes();
                            cipherNotesRunnable = null;
                        }
                    });

                    builder.setNegativeButton("Password", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            isBiometric = false;
                            cipherNotes();
                            cipherNotesRunnable = null;
                        }
                    });
                    AlertDialog alertdialog = builder.create();
                    alertdialog.show();
                }
            };
            new Handler().postDelayed(cipherNotesRunnable, 1000);
        }
    }

    private void cipherNotes() {
        try {
            SecretKey secretKey = getSecretKey(isBiometric);
            if(null != secretKey) {
                Cipher cipher = getCipher();
                if (isEncrypt) {
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                } else {
                    IvParameterSpec ivParams = new IvParameterSpec(loadIV(cipher.getBlockSize()));
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
                }
                if(isBiometric) {
                    biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));
                } else {
                    MainActivity.cipher = cipher;
                    final Intent passwordIntent = new Intent(activity.getApplicationContext(), PasswordFormActivity.class);
                    activity.startActivityForResult(passwordIntent, MainActivity.PasswordActivity);
                }
            } else {
                biometricPrompt.authenticate(promptInfo);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private Cipher getCipher() {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return cipher;
    }

    private String getAlias(boolean isBiometric) {
        String alias = null;
        if(isBiometric) {
            alias = keyStoreAlias;
        } else {
            DataStore dataStore = new DataStore(activity.getApplicationContext());
            alias = dataStore.getPassword();
        }
        return alias;
    }
    private SecretKey getSecretKey(boolean isBiometric) {
        SecretKey secretKey = null;
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            // Before the keystore can be accessed, it must be loaded.
            keyStore.load(null);
            secretKey = (SecretKey) keyStore.getKey(getAlias(isBiometric), null);
        } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return secretKey;
    }

    private void storeSecretKey(String alias) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES);
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();
            storeSecretKey(keyStoreAlias, secretKey);
            storeSecretKey(alias, secretKey);
        } catch (NoSuchAlgorithmException /*| NoSuchProviderException | InvalidAlgorithmParameterException*/ e) {
            e.printStackTrace();
        }
    }

    private void storeSecretKey(String alias, SecretKey secretKey) {
        KeyProtection keyProtection = keyStoreAlias.equals(alias) ?
                new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(true)
                    .setInvalidatedByBiometricEnrollment(true)
                    .setUnlockedDeviceRequired(true)
                    .build() :
               new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(false)
                    .setUnlockedDeviceRequired(true)
                    .build();

        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null);
            keyStore.setEntry(
                    alias,
                    new KeyStore.SecretKeyEntry(secretKey),
                    keyProtection);
        } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException e) {
            e.printStackTrace();
        }

    }

    public void setupKeyStore(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null);
            KeyStore.Entry entry = keyStore.getEntry(keyStoreAlias, null);
            if (null == entry) {
                storeSecretKey(alias);
            }
        } catch (CertificateException | IOException | KeyStoreException | UnrecoverableEntryException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.R)
    public void canAuthenticate(int authenticator) {
        androidx.biometric.BiometricManager biometricManager = androidx.biometric.BiometricManager.from(activity);
        switch (biometricManager.canAuthenticate(authenticator)) {
            case androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS:
                Log.d("MY_APP_TAG", "App can authenticate using biometrics.");
                break;
            case androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                Log.e("MY_APP_TAG", "No biometric features available on this device.");
                break;
            case androidx.biometric.BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                Log.e("MY_APP_TAG", "Biometric features are currently unavailable.");
                break;
            case androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                // Prompts the user to create credentials that your app accepts.
                final Intent enrollIntent = new Intent(Settings.ACTION_BIOMETRIC_ENROLL);
                enrollIntent.putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED, authenticator);
                activity.startActivityForResult(enrollIntent, MainActivity.EnrollActivity);
                break;
            case androidx.biometric.BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED:
                break;
            case androidx.biometric.BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED:
                break;
            case androidx.biometric.BiometricManager.BIOMETRIC_STATUS_UNKNOWN:
                break;
        }
    }
}
