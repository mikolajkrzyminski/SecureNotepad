package com.example.securenotepad;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class DataStore {

    private Context context;
    private SharedPreferences sharedPreferencesNotes;
    private SharedPreferences sharedPreferencesPrefs;
    private final static String notesName = "com.example.securenotepad.notes";
    private final static String prefsName = "com.example.securenotepad.prefs";
    private final static String notesKey = "notes";
    private final static String passwordKey = "password";
    private final static String keyStoreKey = "KeyStore";

    private final static String keyStoreType = "AndroidKeyStore";
    private final static String keyStoreAlias = "NoteApp";

    public DataStore(Context activityContext) {
        sharedPreferencesNotes = activityContext.getSharedPreferences(notesName, Context.MODE_PRIVATE);
        sharedPreferencesPrefs = activityContext.getSharedPreferences(prefsName, Context.MODE_PRIVATE);
    };

    public String getPassword() {
        String password = null;
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null);
            Enumeration<String> aliases = keyStore.aliases();
            while(aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if(!keyStoreAlias.equals(alias)) {
                    password = alias;
                    break;
                }
            }
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return password;
    }

    public void setPassword(String password) {
        sharedPreferencesPrefs.edit().putString(passwordKey, password).apply();
    }

}
