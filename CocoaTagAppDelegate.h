//
//  CocoaTagAppDelegate.h
//  CocoaTag
//
//  Created by Johnno Loggie on 20/11/2010.
//  Copyright 2010 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#define LogString(format,...) [((CocoaTagAppDelegate*) [[NSApplication sharedApplication] delegate]) LogString: [NSString stringWithFormat: format, ##__VA_ARGS__]]

@interface CocoaTagAppDelegate : NSObject <NSApplicationDelegate> {
    NSWindow *window;
	IBOutlet NSTextField* txtURL;
	IBOutlet NSTextView* txtLog;
}

@property (assign) IBOutlet NSWindow *window;


- (IBAction) formatTag: (id) sender;
- (IBAction) writeURL: (id) sender;

- (void) LogString: (NSString*) s;

@end
