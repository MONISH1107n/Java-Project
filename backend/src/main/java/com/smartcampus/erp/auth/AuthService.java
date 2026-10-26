package com.smartcampus.erp.auth;

import com.smartcampus.erp.common.ApiException;
import com.smartcampus.erp.config.AppProperties;
import com.smartcampus.erp.notification.NotificationService;
import com.smartcampus.erp.user.FacultyProfile;
import com.smartcampus.erp.user.FacultyRepository;
import com.smartcampus.erp.user.StudentProfile;
import com.smartcampus.erp.user.StudentRepository;
import com.smartcampus.erp.user.User;
import com.smartcampus.erp.user.UserAccount;
import com.smartcampus.erp.user.UserRepository;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final StudentRepository studentRepository;
    private final FacultyRepository facultyRepository;
    private final PasswordHasher passwordHasher;
    private final JwtService jwtService;
    private final AccountTokenRepository accountTokenRepository;
    private final NotificationService notificationService;
    private final AppProperties properties;

    public AuthService(UserRepository userRepository,
                       StudentRepository studentRepository,
                       FacultyRepository facultyRepository,
                       PasswordHasher passwordHasher,
                       JwtService jwtService,
                       AccountTokenRepository accountTokenRepository,
                       NotificationService notificationService,
                       AppProperties properties) {
        this.userRepository = userRepository;
        this.studentRepository = studentRepository;
        this.facultyRepository = facultyRepository;
        this.passwordHasher = passwordHasher;
        this.jwtService = jwtService;
        this.accountTokenRepository = accountTokenRepository;
        this.notificationService = notificationService;
        this.properties = properties;
    }

    @Transactional
    public LoginResponse login(LoginRequest request) {
        String loginId = request.loginId().trim();
        UserAccount account = userRepository.findByLoginIdOrEmail(loginId)
                .orElseThrow(() -> ApiException.unauthorized("The login ID or password is incorrect."));

        if (!passwordHasher.matches(request.password(), account.passwordHash())) {
            throw ApiException.unauthorized("The login ID or password is incorrect.");
        }
        if ("INACTIVE".equals(account.status())) {
            throw ApiException.forbidden("Account is currently deactivated. Contact the Office of the Registrar.");
        }
        if ("PENDING_SETUP".equals(account.status())) {
            throw ApiException.forbidden("Account setup is not complete. Use the activation token sent by the administrator.");
        }
        if (!account.role().equals(request.role())) {
            String actual = roleLabel(account.role());
            String article = actual.startsWith("A") ? "an" : "a";
            throw ApiException.badRequest("This account is " + article + " " + actual
                    + " account. Select " + actual + " to continue.");
        }

        userRepository.updateLastLogin(account.id(), LocalDateTime.now());
        User user = User.from(new UserAccount(
                account.id(), account.loginId(), account.email(), account.passwordHash(),
                account.role(), account.status(), account.createdAt(),
                LocalDateTime.now(), account.avatarUrl()));
        StudentProfile student = studentRepository.findByUserId(account.id()).orElse(null);
        FacultyProfile faculty = facultyRepository.findByUserId(account.id()).orElse(null);
        String displayName = displayName(user, student, faculty);
        String token = jwtService.issue(user.id(), user.role(), user.loginId(), displayName);

        return new LoginResponse(
                token,
                "Bearer",
                properties.jwt().ttlMinutes() * 60,
                user,
                student,
                faculty);
    }

    public MeResponse me() {
        AuthPrincipal principal = AuthContext.require();
        UserAccount account = userRepository.findById(principal.userId())
                .orElseThrow(() -> ApiException.unauthorized("Your account no longer exists."));
        return new MeResponse(
                User.from(account),
                studentRepository.findByUserId(account.id()).orElse(null),
                facultyRepository.findByUserId(account.id()).orElse(null),
                notificationService.unreadCount(account.id()));
    }

    public List<DemoAccount> demoAccounts() {
        if (properties.demo() == null || !properties.demo().enabled()) {
            return List.of();
        }
        List<DemoAccount> accounts = new ArrayList<>();
        accounts.add(new DemoAccount("ADMIN", "Administrator", "admin", "admin123",
                "Manage students, faculty, academics, results, and announcements.", false));
        accounts.add(new DemoAccount("FACULTY", "Faculty", "prof.rajesh", "faculty123",
                "Mark attendance, enter marks, and respond to complaints for your sections.", false));
        accounts.add(new DemoAccount("STUDENT", "Student", "21cs101", "student123",
                "View your timetable, attendance, results, and complaints.", false));
        accounts.add(new DemoAccount("STUDENT", "Student (At-risk test)", "21cs104", "student123",
                "At-risk attendance trigger test account (<75%).", true));
        return accounts;
    }

    @Transactional
    public User activate(ActivateRequest request) {
        AccountToken token = accountTokenRepository.findUsable(request.token())
                .orElseThrow(() -> ApiException.badRequest("Activation token is invalid, expired, or already used."));
        UserAccount account = userRepository.findById(token.userId())
                .orElseThrow(() -> ApiException.notFound("Account not found."));
        userRepository.updatePassword(account.id(), passwordHasher.hash(request.password()));
        userRepository.updateStatus(account.id(), "ACTIVE");
        accountTokenRepository.markUsed(token.id());
        User user = User.from(new UserAccount(
                account.id(), account.loginId(), account.email(), account.passwordHash(),
                account.role(), "ACTIVE", account.createdAt(), account.lastLogin(), account.avatarUrl()));
        notificationService.notifyUser(account.id(), "Account Activated",
                "Your Smart Campus account is active. You can now sign in with your new password.",
                "GENERAL_ANNOUNCEMENT", account.id());
        return user;
    }

    private String displayName(User user, StudentProfile student, FacultyProfile faculty) {
        if (student != null && student.fullName() != null && !student.fullName().isBlank()) {
            return student.fullName();
        }
        if (faculty != null && faculty.fullName() != null && !faculty.fullName().isBlank()) {
            return faculty.fullName();
        }
        if (user != null && "ADMIN".equals(user.role())) {
            return "Dr. A. K. Sundaram (Registrar)";
        }
        if (user != null && user.loginId() != null && !user.loginId().isBlank()) {
            return user.loginId();
        }
        return "User";
    }

    private String roleLabel(String role) {
        return switch (role) {
            case "ADMIN" -> "Administrator";
            case "FACULTY" -> "Faculty";
            default -> "Student";
        };
    }
}
