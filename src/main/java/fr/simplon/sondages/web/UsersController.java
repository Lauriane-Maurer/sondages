package fr.simplon.sondages.web;

import fr.simplon.sondages.dto.UserForm;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;

import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

@Controller
public class UsersController
    {
        private PasswordEncoder passwordEncoder;
        private UserDetailsManager userDetailsManager;
        @Autowired
        public UsersController(
                PasswordEncoder pPasswordEncoder,
                UserDetailsManager pUserDetailsManager)
                {
                    passwordEncoder = pPasswordEncoder;
                    userDetailsManager = pUserDetailsManager;
                }

        @GetMapping(path = "/admin/createUser")
        public String getCreateUserForm (@ModelAttribute(name = "user") UserForm user, Model model)
        {
            if (user == null || !model.containsAttribute("user"))
            {model.addAttribute("user", new UserForm());}
            return "/admin/createUser";
        }

        @GetMapping(path = "/inscription")
        public String getRegistrationForm (@ModelAttribute(name = "user") UserForm user, Model model)
        {
            if (user == null || !model.containsAttribute("user"))
            {model.addAttribute("user", new UserForm());}
            return "/inscription";
        }


        @PostMapping("/admin/createUser")
        @Transactional
        public String createUser(
                @Valid @ModelAttribute(name = "user") UserForm user,
                BindingResult validation, Model model)
        {
            if (!user.getPassword().equals(user.getConfirmPassword()))
            {
                user.setConfirmPassword("");
                validation.addError(new FieldError("user", "confirmPassword",
                        "Les mots de passe ne correspondent pas"));
            }
            if (userDetailsManager.userExists(user.getLogin()))
            {
                user.setLogin("");
                validation.addError(new ObjectError("user", "Cet utilisateur existe déjà"));
            }
            if (validation.hasErrors())
            {
                return "/admin/createUser";
            }
            String encodedPassword = passwordEncoder.encode(user.getPassword());
            // Roles for new user
            Collection<? extends GrantedAuthority> roles = Arrays.asList(new SimpleGrantedAuthority("USER"));
            UserDetails userDetails = new User(user.getLogin(), encodedPassword, roles);
            // Create the account in database with all its roles
            userDetailsManager.createUser(userDetails);
            return "redirect:/index";
        }

        @PostMapping("/inscription")
        @Transactional
        public String registration(
                @Valid @ModelAttribute(name = "user") UserForm user,
                BindingResult validation, Model model)
        {
            if (!user.getPassword().equals(user.getConfirmPassword()))
            {
                user.setConfirmPassword("");
                validation.addError(new FieldError("user", "confirmPassword",
                        "Les mots de passe ne correspondent pas"));
            }
            if (userDetailsManager.userExists(user.getLogin()))
            {
                user.setLogin("");
                validation.addError(new ObjectError("user", "Cet utilisateur existe déjà"));
            }
            if (validation.hasErrors())
            {
                return "/inscription";
            }
            String encodedPassword = passwordEncoder.encode(user.getPassword());
            // Roles for new user
            Collection<? extends GrantedAuthority> roles = Arrays.asList(new SimpleGrantedAuthority("USER"));
            UserDetails userDetails = new User(user.getLogin(), encodedPassword, roles);
            // Create the account in database with all its roles
            userDetailsManager.createUser(userDetails);
            return "redirect:/index";
        }


        @GetMapping(path = "/connexion")
        public String Login(@ModelAttribute(name = "user") UserForm user, Model model)
        {
            if (user == null || !model.containsAttribute("user"))
            {model.addAttribute("user", new UserForm());}
            return "connexion";
        }

        @GetMapping(path = "/deconnexion")
        public String logout(HttpServletRequest request) {
            SecurityContextHolder.getContext().setAuthentication(null);
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            return "redirect:/";
        }

        @GetMapping(path = "/modification")
        public String Update(@ModelAttribute(name ="user") UserForm user, Model model)
        {
            if (user == null || !model.containsAttribute("user"))
            {model.addAttribute("user", new UserForm());}
            return "inscription";
        }



    }


