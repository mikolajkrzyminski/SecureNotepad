package com.example.securenotepad;

import androidx.appcompat.app.AppCompatActivity;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

public class PasswordFormActivity extends AppCompatActivity {

    private enum State{ CheckPassword, SetupPassword, ChangePassword}

    private State state;
    private TextView textView0;
    private TextView textView1;
    private TextView textView2;
    private EditText editText0;
    private EditText editText1;
    private EditText editText2;
    private MenuItem changePassButton;

    public void setState(State newState){
        state = newState;
        if(State.CheckPassword.equals(newState)) {
            textView0.setVisibility(View.VISIBLE);
            editText0.setVisibility(View.VISIBLE);
            textView1.setVisibility(View.GONE);
            editText1.setVisibility(View.GONE);
            textView2.setVisibility(View.GONE);
            editText2.setVisibility(View.GONE);
            changePassButton.setVisible(false);
        } else if(State.SetupPassword.equals(newState)) {
            textView0.setVisibility(View.GONE);
            editText0.setVisibility(View.GONE);
            textView1.setVisibility(View.VISIBLE);
            editText1.setVisibility(View.VISIBLE);
            textView2.setVisibility(View.VISIBLE);
            editText2.setVisibility(View.VISIBLE);
            changePassButton.setVisible(false);
        } else if(State.ChangePassword.equals(newState)) {
            textView0.setVisibility(View.VISIBLE);
            editText0.setVisibility(View.VISIBLE);
            textView1.setVisibility(View.VISIBLE);
            editText1.setVisibility(View.VISIBLE);
            textView2.setVisibility(View.VISIBLE);
            editText2.setVisibility(View.VISIBLE);
            changePassButton.setVisible(false);
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.change_password_button, menu);
        textView0 = findViewById(R.id.textView0);
        textView1 = findViewById(R.id.textView1);
        textView2 = findViewById(R.id.textView2);
        editText0 = findViewById(R.id.editText0);
        editText1 = findViewById(R.id.editText1);
        editText2 = findViewById(R.id.editText2);
        changePassButton = menu.findItem(R.id.changepass);
        DataStore dataStore = new DataStore(getApplicationContext());
        //dataStore.clearSharedPreferences();
        if(null == dataStore.getPassword()) {
            setState(State.SetupPassword);
        } else {
            setState(State.CheckPassword);
        }
        return super.onCreateOptionsMenu(menu);
    }

    // handle button activities
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.changepass) {
            if(State.CheckPassword.equals(state)) setState(State.ChangePassword);
            else if(State.ChangePassword.equals(state)) setState(State.CheckPassword);
        }
        return super.onOptionsItemSelected(item);
    }

    private boolean checkOldPassword() {
        String enteredPassword = editText0.getText().toString();
        //load the password
        DataStore dataStore = new DataStore(getApplicationContext());
        String encryptedPassword = dataStore.getPassword();
        if(CryptoTools.checkPasswordBcrypt(encryptedPassword, enteredPassword)) {
           return true;
        } else {
            Toast.makeText(getApplicationContext(), "Wrong password!", Toast.LENGTH_SHORT).show();
            return false;
        }
    }

    private boolean checkNewPassword() {
        String password1 = editText1.getText().toString();
        String password2 = editText2.getText().toString();
        if(password1.equals(password2)) {
            if(password1.length() < 10) {
                Toast.makeText(getApplicationContext(), "At least 10 chars!", Toast.LENGTH_SHORT).show();
                return false;
            } else {
                return true;
            }
        } else {
            //there is no match on the passwords
            Toast.makeText(getApplicationContext(), "Passwords don't match!", Toast.LENGTH_SHORT).show();
            return false;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_password_form);

        Button button = findViewById(R.id.button);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(State.CheckPassword.equals(state)) {
                    if(checkOldPassword()){
                        Intent returnIntent = new Intent();
                        returnIntent.putExtra("result", editText0.getText().toString());
                        setResult(Activity.RESULT_OK, returnIntent);
                        finish();
                    }
                } else if(State.SetupPassword.equals(state)) {
                    if(checkNewPassword()) {
                        Intent returnIntent = new Intent();
                        returnIntent.putExtra("result", editText1.getText().toString());
                        setResult(Activity.RESULT_OK, returnIntent);
                        finish();
                    }
                } else if(State.ChangePassword.equals(state)) {
                    if(checkOldPassword() && checkNewPassword()) {
                        Intent returnIntent = new Intent();
                        returnIntent.putExtra("result", editText1.getText().toString());
                        setResult(Activity.RESULT_OK, returnIntent);
                        finish();
                    }
                }
            }
        });
    }
}