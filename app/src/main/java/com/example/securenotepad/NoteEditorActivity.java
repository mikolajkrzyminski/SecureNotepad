package com.example.securenotepad;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.Menu;
import android.view.MenuItem;
import android.view.inputmethod.EditorInfo;
import android.widget.EditText;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import java.util.HashSet;

public class NoteEditorActivity extends AppCompatActivity {

    public int noteID;
    private EditText editText;
    private FingerprintManager fingerprintManager;

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // R.menu.savenote_button is a reference to an xml file named savenote_button.xml which should be inside your res/menu directory.
        // If you don't have res/menu, just create a directory named "menu" inside res
        getMenuInflater().inflate(R.menu.savenote_button, menu);
        return super.onCreateOptionsMenu(menu);
    }

    // handle button activities
    @RequiresApi(api = Build.VERSION_CODES.R)
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {

        int id = item.getItemId();
        if (id == R.id.confirm_button) {
            if(editText.getText().toString().isEmpty()) {
                if(noteID != -1) MainActivity.notes.remove(noteID);
            } else {
                if(noteID == -1) {
                    MainActivity.notes.add(editText.getText().toString());
                } else {
                    MainActivity.notes.set(noteID, editText.getText().toString());
                }
            }
            MainActivity.arrayAdapter.notifyDataSetChanged();
            //DataStore dataStore = new DataStore(getApplicationContext());
            //dataStore.updateNotes(MainActivity.notes, MainActivity.publicKey);
        }
        finish();
        return super.onOptionsItemSelected(item);
    }

    @RequiresApi(api = Build.VERSION_CODES.R)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_note_editor);

        editText = (EditText)findViewById(R.id.editText);
        Intent intent = getIntent();
        noteID = intent.getIntExtra("noteID", -1);         //default value is -1 (in case of intent error)

        editText.setText(noteID != -1 ? MainActivity.notes.get(noteID) : "");
    }
}