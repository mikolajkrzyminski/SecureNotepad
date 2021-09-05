package com.example.securenotepad;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.provider.Settings;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;

import javax.crypto.Cipher;

public class MainActivity extends AppCompatActivity {

    static ArrayList<String> notes = new ArrayList<String>();
    static ArrayAdapter<String> arrayAdapter;
    static FingerprintManager fingerprintManager;

    public static Cipher cipher;
    public static final int EnrollActivity   = 100;
    public static final int PasswordActivity = 101;

    @Override
    public boolean onCreateOptionsMenu(Menu menu)
    {
        getMenuInflater().inflate(R.menu.add_note_button, menu);
        return super.onCreateOptionsMenu(menu);
    }

    @RequiresApi(api = Build.VERSION_CODES.R)
    @Override
    public boolean onOptionsItemSelected(MenuItem item)
    {
        super.onOptionsItemSelected(item);

        if(item.getItemId() == R.id.addnote)
        {
            Intent intent = new Intent(getApplicationContext(), NoteEditorActivity.class);
            startActivity(intent);
            return true;
        } else if(item.getItemId() == R.id.saveAll) {
            fingerprintManager.cipherNotes(true);
        }

        return false;
    }

    @RequiresApi(api = Build.VERSION_CODES.R)
    @Override
    public void onBackPressed() {
        new AlertDialog.Builder(MainActivity.this)
                .setIcon(android.R.drawable.ic_dialog_alert)
                .setTitle("Save?")
                .setMessage("Do you want to save all your notes?")
                .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                    @RequiresApi(api = Build.VERSION_CODES.R)
                    @Override
                    public void onClick(DialogInterface dialog, int which)
                    {
                        fingerprintManager.exitApp = true;
                        fingerprintManager.cipherNotes(true);
                    }
                })
                .setNegativeButton("No", new DialogInterface.OnClickListener() {
                    @RequiresApi(api = Build.VERSION_CODES.R)
                    @Override
                    public void onClick(DialogInterface dialog, int which)
                    {
                        finish();
                    }
                })
                .show();
    }

    @RequiresApi(api = Build.VERSION_CODES.R)
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if(EnrollActivity == requestCode) {
            final Intent passwordIntent = new Intent(getApplicationContext(), PasswordFormActivity.class);
            startActivityForResult(passwordIntent, MainActivity.PasswordActivity);
        } else if(PasswordActivity == requestCode) {
            if(resultCode == Activity.RESULT_OK) {
                DataStore dataStore = new DataStore(getApplicationContext());
                String encryptedPassword = dataStore.getPassword();
                if(null == encryptedPassword) {
                    String plainPassword = data.getStringExtra("result");
                    encryptedPassword = CryptoTools.getPasswordBcrypt(plainPassword);
                    fingerprintManager.setupKeyStore(encryptedPassword);
                } else {
                    fingerprintManager.onAuthenticationSucceededLocal(cipher);
                    cipher = null;
                }
            } else if (resultCode == Activity.RESULT_CANCELED) {
                //Write your code if there's no result
            }
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.R)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ListView listView = (ListView) findViewById(R.id.listView);

        DataStore dataStore = new DataStore(getApplicationContext());
        cipher = null;

        arrayAdapter = new ArrayAdapter<String>(this, android.R.layout.simple_list_item_1, notes);
        listView.setAdapter(arrayAdapter);

        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id)
            {
                Intent intent = new Intent(getApplicationContext(), NoteEditorActivity.class);
                intent.putExtra("noteID", position);            //to tell us which row of listView was tapped
                startActivity(intent);
            }
        });

        listView.setOnItemLongClickListener(new AdapterView.OnItemLongClickListener() {
            @Override
            public boolean onItemLongClick(AdapterView<?> parent, View view, final int position, long id)
            {
                new AlertDialog.Builder(MainActivity.this)
                        .setIcon(android.R.drawable.ic_dialog_alert)
                        .setTitle("Delete?")
                        .setMessage("Are you sure you want to delete this note?")
                        .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which)
                            {
                                notes.remove(position);
                                arrayAdapter.notifyDataSetChanged();
                                fingerprintManager.cipherNotes(true);
                            }
                        })

                        .setNegativeButton("No", null)
                        .show();

                return true;
            }
        });

        fingerprintManager = FingerprintManager.getInstance(this);
        fingerprintManager.canAuthenticate(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG);
        if(null != dataStore.getPassword()) fingerprintManager.cipherNotes(false);
    }
}