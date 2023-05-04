package fr.simplon.sondages.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class UserForm {

    @NotBlank
    @Size(min=1,max=255)
    private String login;
    @NotBlank
    @Size(min=1,max=255)
    private String password;
    @NotBlank
    @Size(min=1,max=255)
    private String confirmPassword;


    public String getLogin() {
        return login;
    }
    public void setLogin(String login) {
        this.login = login;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public String getConfirmPassword() {
        return confirmPassword;
    }
    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }
}

