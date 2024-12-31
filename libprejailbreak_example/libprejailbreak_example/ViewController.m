// ViewController.m
// libprejailbreak_example, 2024

#import "ViewController.h"
#include <libprejailbreak/libprejailbreak.h>
#include <libprejailbreak/exploit.h>
#include <libprejailbreak/escalation.h>
#include <libprejailbreak/tfp0.h>
#include <libprejailbreak/offsets.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    UIButton *goButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [goButton setTitle:@"Go" forState:UIControlStateNormal];
    goButton.translatesAutoresizingMaskIntoConstraints = NO;
    goButton.frame = CGRectMake(100, 100, 100, 50);
    [goButton addTarget:self action:@selector(demo) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:goButton];
    
    [NSLayoutConstraint activateConstraints:@[
        [goButton.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [goButton.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [goButton.widthAnchor constraintEqualToConstant:100],
        [goButton.heightAnchor constraintEqualToConstant:50]
    ]];
}

- (void)demo {
    if (kernel_rw_init() != 0) {
        printf("ERROR: failed to exploit kernel\n");
        return;
    }
    
    proc_fix_setuid_setgid(proc_self()); // Allow us to become root
    proc_set_mac_label(proc_self(), 1, 0); // Remove sandbox
    proc_update_csflags(proc_self()); // Update CS flags so we become a platform binary
    
    // Escalate to root
    setuid(0);
    setuid(0);
    
    printf("getuid() -> %d\n", getuid());
    
    if (gOffsets.major < MAJOR(14)) {
        if (tfp0_init() != 0) {
            printf("ERROR: failed to initialise tfp0\n");
        }
    }
    
    setuid(501);
}

@end
