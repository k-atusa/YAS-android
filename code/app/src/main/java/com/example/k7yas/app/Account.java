package com.example.k7yas.app;

import java.io.Serializable;

public class Account implements Serializable {
    public String username;
    public String password;
    public String kfPath;
    
    // Settings
    public String packType;
    public String imgType;
    public String encType;
    public boolean inMemView;

    public Account() {
        this.username = "";
        this.password = "";
        this.kfPath = "";
        this.packType = "Default";
        this.imgType = "Default";
        this.encType = "Default";
        this.inMemView = false;
    }
}
