package ru.alls.controller;

import ru.alls.entities.UserDataSet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import ru.alls.userservices.UserServiceImpl;
import java.util.ArrayList;

@Controller
public class UserController {

    UserServiceImpl userServiceImpl;

    @Autowired
    public UserController(UserServiceImpl userServiceImpl) {
        this.userServiceImpl = userServiceImpl;
    }

    @RequestMapping(value = "/user/user", method = RequestMethod.GET)
    public ModelAndView userMainPage(){
        ModelAndView mv = new ModelAndView("/user/user");
        return mv;
    }

    @RequestMapping(value = {"/admin/findUser"}, method = RequestMethod.GET)
    public ModelAndView findUser(@RequestParam("name") String login) {
        ModelAndView mv = new ModelAndView("/admin/findUser");
        UserDataSet userDataSet = userServiceImpl.findByLogin(login);
        if (userDataSet != null) {
            mv.addObject("userDataSets", userDataSet);
            mv.addObject("headerMessage", "User exist");
        } else  {
            mv.addObject("headerMessage", "User does not exist");
        }
        return mv;

    }

    @RequestMapping(value = {"/", "home"})
    String get() {
        return "index";
    }

    @RequestMapping(value = {"/admin/adminhome"}, method = RequestMethod.GET)
    public ModelAndView showUsers(Model model) {
        ModelAndView mv = new ModelAndView();
        ArrayList<UserDataSet> userDataSets = (ArrayList<UserDataSet>) userServiceImpl.getAllUsers();
        mv.addObject("userDataSets", userDataSets);
        mv.setViewName("admin/adminhome");
        return mv;
    }

    @RequestMapping(value = "/admin/editUser/{id}", method = RequestMethod.GET)
    public ModelAndView displayEditUserForm(@PathVariable Long id) {
        ModelAndView mv = new ModelAndView("/admin/editUser");
        UserDataSet user = userServiceImpl.getUserById(id);
        mv.addObject("headerMessage", "Edit User Details");
        mv.addObject("user", user);
        return mv;
    }

    @RequestMapping(value = "/admin/editUser/{id}", method = RequestMethod.POST)
    public ModelAndView saveEditedUser(@ModelAttribute UserDataSet user, BindingResult result) {
        ModelAndView mv = new ModelAndView("redirect:/admin/adminhome");

        if (result.hasErrors()) {
            System.out.println(result.toString());
            return new ModelAndView("error");
        }
        boolean isSaved = userServiceImpl.saveUser(user);
        if (!isSaved) {

            return new ModelAndView("error");
        }

        return mv;
    }

    @RequestMapping(value = "/admin/deleteUser/{id}", method = RequestMethod.GET)
    public ModelAndView deleteUserById(@PathVariable Long id) {
        boolean isDeleted = userServiceImpl.deleteUserById(id);
        System.out.println("User deletion respone: " + isDeleted);
        ModelAndView mv = new ModelAndView("redirect:/admin/adminhome");
        return mv;
    }

    @RequestMapping(value = "/admin/addUser", method = RequestMethod.GET)
    public ModelAndView displayNewUserForm() {
        ModelAndView mv = new ModelAndView("admin/add");
        mv.addObject("headerMessage", "Add User Details");
        mv.addObject("user", new UserDataSet());
        return mv;
    }

    @RequestMapping(value = "/admin/addUser", method = RequestMethod.POST)
    public ModelAndView saveNewUser(@ModelAttribute UserDataSet user, BindingResult result) {
        ModelAndView mv = new ModelAndView("redirect:/admin/adminhome");

        if (result.hasErrors()) {
            return new ModelAndView("error");
        }
        boolean isAdded = userServiceImpl.saveUser(user);
        if (isAdded) {
            mv.addObject("message", "New user successfully added");
        } else {
            return new ModelAndView("error");
        }

        return mv;
    }
}
