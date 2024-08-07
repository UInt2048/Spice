//
//  Archive.h
//
//  Created by Sam Bingner on 1/4/19.
//  Copyright © 2019 Sam Bingner. All rights reserved.
//

#ifndef _ARCHIVE_FILE_H
#define _ARCHIVE_FILE_H
#import <Foundation/Foundation.h>
#import <archive.h>

#ifdef __IPHONE_9_0
typedef NSArray<NSString*> FileArray;
#else
typedef NSArray FileArray;
#endif

@interface ArchiveFile : NSObject
@property (strong, readonly) FileArray* files;

+ (ArchiveFile*)archiveWithFile:(NSString*)filename;
+ (ArchiveFile*)archiveWithFd:(int)fd;
- (ArchiveFile*)initWithFile:(NSString*)filename;
- (ArchiveFile*)initWithFd:(int)fd;
- (BOOL)contains:(NSString*)file;
- (FileArray*)files;
- (BOOL)extract;
- (BOOL)extractFileNum:(int)fileNum toFd:(int)fd;
- (BOOL)extract:(NSString*)file toPath:(NSString*)path;
- (BOOL)extractWithFlags:(int)flags;
- (BOOL)extractToPath:(NSString*)path;
- (BOOL)extractToPath:(NSString*)path overWriteDirectories:(BOOL)overwrite_dirs;
- (BOOL)extractToPath:(NSString*)path withFlags:(int)flags;
- (BOOL)extractToPath:(NSString*)path withFlags:(int)flags overWriteDirectories:(BOOL)overwrite_dirs;
@end

#endif /* _ARCHIVE_FILE_H */
