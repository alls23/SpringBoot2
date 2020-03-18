package ru.alls.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;
import ru.alls.userservices.UserServiceImpl;


import java.security.Principal;

@Controller
public class AuthController {
   private UserServiceImpl userServiceImpl;

   @Autowired
   public AuthController(UserServiceImpl userService) {
       this.userServiceImpl = userService;
   }

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public ModelAndView login(Model model, String error, String logout, Principal user) {
        ModelAndView mv = new ModelAndView("/index");
       if(user != null) {
           mv.addObject("message", "alredy logged");
           return mv;
       }
        return new ModelAndView("/login");
    }

//    @RequestMapping(value="/logout", method = RequestMethod.GET)
//    public String logoutPage (HttpServletRequest request, HttpServletResponse response) {
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        if (auth != null){
//            new SecurityContextLogoutHandler().logout(request, response, auth);
//        }
//        return "redirect:/login?logout";//You can redirect wherever you want, but generally it's a good practice to show login screen again.
//    }

}
