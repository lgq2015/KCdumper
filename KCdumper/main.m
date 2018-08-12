#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import "sqlite3.h"

////printToStdOut 不能使用中文
void printToStdOut(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *formattedString = [[NSString alloc] initWithFormat: format arguments: args];
    va_end(args);
    [[NSFileHandle fileHandleWithStandardOutput] writeData: [formattedString dataUsingEncoding: NSNEXTSTEPStringEncoding]];
	[formattedString release];
}

void printUsage() {
	printToStdOut(@"Usage: keychain_dumper [-e]|[-h]|[-agnick]\n");
	printToStdOut(@"<no flags>: Dump Password Keychain Items (Generic Password, Internet Passwords)\n");
	printToStdOut(@"-a: Dump All Keychain Items (Generic Passwords, Internet Passwords, Identities, Certificates, and Keys)\n");
	printToStdOut(@"-e: Dump Entitlements\n");
	printToStdOut(@"-g: Dump Generic Passwords\n");
	printToStdOut(@"-n: Dump Internet Passwords\n");
	printToStdOut(@"-i: Dump Identities\n");
	printToStdOut(@"-c: Dump Certificates\n");
	printToStdOut(@"-k: Dump Keys\n");
    printToStdOut(@"-z: clean icloud acount data:  delete from ZACCOUNT where ZUSERNAME <> \"\"\n");
}

void dumpKeychainEntitlements() {
	NSLog(@"==============开始打印enttltments.xml这个文件===================>");
	NSString *databasePath = @"/var/Keychains/keychain-2.db";
    const char *dbpath = [databasePath UTF8String];
    sqlite3 *keychainDB;
    sqlite3_stmt *statement;
	NSMutableString *entitlementXML = [NSMutableString stringWithString:@"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                       "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                                       "<plist version=\"1.0\">\n"
                                       "\t<dict>\n"
                                       "\t\t<key>keychain-access-groups</key>\n"
                                       "\t\t<array>\n"];
	
    if (sqlite3_open(dbpath, &keychainDB) == SQLITE_OK) {
        const char *query_stmt = "SELECT DISTINCT agrp FROM genp UNION SELECT DISTINCT agrp FROM inet";
		
        if (sqlite3_prepare_v2(keychainDB, query_stmt, -1, &statement, NULL) == SQLITE_OK) {
			while(sqlite3_step(statement) == SQLITE_ROW) {
				NSString *group = [[NSString alloc] initWithUTF8String:(const char *) sqlite3_column_text(statement, 0)];
				
                [entitlementXML appendFormat:@"\t\t\t<string>%@</string>\n", group];
                [group release];
            }
            sqlite3_finalize(statement);
        }
        else {
            printToStdOut(@"Unknown error querying keychain database\n");
		}
		[entitlementXML appendString:@"\t\t</array>\n"
         "\t</dict>\n"
         "</plist>\n"];
		sqlite3_close(keychainDB);
		printToStdOut(@"%@", entitlementXML);
	} else {
		printToStdOut(@"Unknown error opening keychain database\n");
	}
}

// 配置成命令行的形式
NSMutableArray *getCommandLineOptions(int argc, char **argv) {
	NSLog(@"==============开始获取命令行配置===================");
	NSMutableArray *arguments = [[NSMutableArray alloc] init];
	int argument;
	if (argc == 1) {
		[arguments addObject:(id)kSecClassGenericPassword];
		[arguments addObject:(id)kSecClassInternetPassword];
		return [arguments autorelease];
	}
	// 判断命令行中有其他字段 -a -e 等
	while ((argument = getopt (argc, argv, "aegnickhz")) != -1) {
		switch (argument) {
			case 'a':
				[arguments addObject:(id)kSecClassGenericPassword];
				[arguments addObject:(id)kSecClassInternetPassword];
				[arguments addObject:(id)kSecClassIdentity];
				[arguments addObject:(id)kSecClassCertificate];
				[arguments addObject:(id)kSecClassKey];
				return [arguments autorelease];
			case 'e':
				// if they want to dump entitlements we will assume they don't want to dump anything else
				[arguments addObject:@"dumpEntitlements"];
				return [arguments autorelease];
			case 'g':
				[arguments addObject:(id)kSecClassGenericPassword];
				break;
			case 'n':
				[arguments addObject:(id)kSecClassInternetPassword];
				break;
			case 'i':
				[arguments addObject:(id)kSecClassIdentity];
				break;
			case 'c':
				[arguments addObject:(id)kSecClassCertificate];
				break;
			case 'k':
				[arguments addObject:(id)kSecClassKey];
				break;
			case 'h':
				printUsage();
				break;
			case '?':
			    printUsage();
			 	exit(EXIT_FAILURE);
            case 'z':
            {//kncleanAccount3Sqlite
                [arguments addObject:@"kncleanAccount3Sqlite"];
                return [arguments autorelease];
            }
			default:
				continue;
		}
	}

	return [arguments autorelease];

}

NSArray * getKeychainObjectsForSecClass(CFTypeRef kSecClassType) {
	NSLog(@"==============获取keychain表:%@表===================",kSecClassType);
	NSMutableDictionary *genericQuery = [[NSMutableDictionary alloc] init];
	
	[genericQuery setObject:(id)kSecClassType forKey:(id)kSecClass];
	[genericQuery setObject:(id)kSecMatchLimitAll forKey:(id)kSecMatchLimit];
	[genericQuery setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnAttributes];
	[genericQuery setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnRef];
	[genericQuery setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
	NSLog(@"==============获取keychain表:%@表,kSecClass:%@,kSecMatchLimit:%@,kSecReturnAttributes:%@,kSecReturnRef:%@,kSecReturnData :%@===================",kSecClassType,kSecClass,kSecMatchLimit,kSecReturnAttributes,kSecReturnRef,kSecReturnData);
	NSArray *keychainItems = nil;
	if (SecItemCopyMatching((CFDictionaryRef)genericQuery, (CFTypeRef *)&keychainItems) != noErr)
	{
		NSLog(@"--------没有找到数据库表--------------");
		keychainItems = nil;
	}
	NSLog(@"--------找到数据库表--------------");
	[genericQuery release];
	return keychainItems;
}

NSString * getEmptyKeychainItemString(CFTypeRef kSecClassType) {
	NSLog(@"==============获取空keychain条目===================>");
	if (kSecClassType == kSecClassGenericPassword) {
		return @"No Generic Password Keychain items found.\n";
	}
	else if (kSecClassType == kSecClassInternetPassword) {
		return @"No Internet Password Keychain items found.\n";	
	} 
	else if (kSecClassType == kSecClassIdentity) {
		return @"No Identity Keychain items found.\n";
	}
	else if (kSecClassType == kSecClassCertificate) {
		return @"No Certificate Keychain items found.\n";	
	}
	else if (kSecClassType == kSecClassKey) {
		return @"No Key Keychain items found.\n";	
	}
	else {
		return @"Unknown Security Class\n";
	}
	
}

void printGenericPassword(NSDictionary *passwordItem) {
	NSLog(@"==============打印普通密码===================>");
	printToStdOut(@"Generic Password\n");
	printToStdOut(@"----------------\n");
	printToStdOut(@"Service: %@\n", [passwordItem objectForKey:(id)kSecAttrService]);
	printToStdOut(@"Account: %@\n", [passwordItem objectForKey:(id)kSecAttrAccount]);
	printToStdOut(@"Entitlement Group: %@\n", [passwordItem objectForKey:(id)kSecAttrAccessGroup]);
	printToStdOut(@"Label: %@\n", [passwordItem objectForKey:(id)kSecAttrLabel]);
	printToStdOut(@"Generic Field: %@\n", [[passwordItem objectForKey:(id)kSecAttrGeneric] description]);
	NSData* passwordData = [passwordItem objectForKey:(id)kSecValueData];
	printToStdOut(@"Keychain Data: %@\n\n", [[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding]);
	printToStdOut(@"kSecAttrSynchronizable:%@\n",[[passwordItem objectForKey:(id)kSecAttrSynchronizable] description]);
    
    //CFStringRef knkSecAttrSyncViewHint = [passwordItem objectForKey:(id)kSecAttrSyncViewHint];
    printToStdOut(@"kSecAttrSyncViewHint:%@\n",@"Do not print temporarily");//Segmentation fault: 11

    
    //    @constant kSecAttrSyncViewHint Specifies a dictionary key whose value is
//    a CFStringRef. This value is part of the primary key of each item, and
  //  can be used to help distiguish Sync Views when defining their
    //queries. iOS and sychronizable items only.
    //printToStdOut(@"kSecAttrSyncViewHint:%@\n",@"Do not print temporarily");//Segmentation fault: 11
//printToStdOut 不能使用中文
}

void printInternetPassword(NSDictionary *passwordItem) {
	NSLog(@"==============打印InternetPassword===================>");
	printToStdOut(@"Internet Password\n");
	printToStdOut(@"-----------------\n");
	printToStdOut(@"Server: %@\n", [passwordItem objectForKey:(id)kSecAttrServer]);
	printToStdOut(@"Account: %@\n", [passwordItem objectForKey:(id)kSecAttrAccount]);
	printToStdOut(@"Entitlement Group: %@\n", [passwordItem objectForKey:(id)kSecAttrAccessGroup]);
	printToStdOut(@"Label: %@\n", [passwordItem objectForKey:(id)kSecAttrLabel]);
	NSData* passwordData = [passwordItem objectForKey:(id)kSecValueData];
	printToStdOut(@"Keychain Data: %@\n\n", [[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding]);
}


void printCertificate(NSDictionary *certificateItem) {
	NSLog(@"==============打印证书===================>");
	SecCertificateRef certificate = (SecCertificateRef)[certificateItem objectForKey:(id)kSecValueRef];

	CFStringRef summary;
	summary = SecCertificateCopySubjectSummary(certificate);
	printToStdOut(@"Certificate\n");
	printToStdOut(@"-----------\n");
	printToStdOut(@"Summary: %@\n", (NSString *)summary);
	CFRelease(summary);
	printToStdOut(@"Entitlement Group: %@\n", [certificateItem objectForKey:(id)kSecAttrAccessGroup]);
	printToStdOut(@"Label: %@\n", [certificateItem objectForKey:(id)kSecAttrLabel]);
	printToStdOut(@"Serial Number: %@\n", [certificateItem objectForKey:(id)kSecAttrSerialNumber]);
	printToStdOut(@"Subject Key ID: %@\n", [certificateItem objectForKey:(id)kSecAttrSubjectKeyID]);
	printToStdOut(@"Subject Key Hash: %@\n\n", [certificateItem objectForKey:(id)kSecAttrPublicKeyHash]);
	
}

void printKey(NSDictionary *keyItem) {
	NSLog(@"==============打印Key===================>");
//	NSString *keyClass = @"Unknown";
//	CFTypeRef _keyClass = [keyItem objectForKey:(id)kSecAttrKeyClass];
//
//	if ([[(id)_keyClass description] isEqual:(id)kSecAttrKeyClassPublic]) {
//		keyClass = @"Public";
//	}
//	else if ([[(id)_keyClass description] isEqual:(id)kSecAttrKeyClassPrivate]) {
//		keyClass = @"Private";
//	}
//	else if ([[(id)_keyClass description] isEqual:(id)kSecAttrKeyClassSymmetric]) {
//		keyClass = @"Symmetric";
//	}

	printToStdOut(@"Key\n");
	printToStdOut(@"---\n");
	printToStdOut(@"Entitlement Group: %@\n", [keyItem objectForKey:(id)kSecAttrAccessGroup]);
	printToStdOut(@"Label: %@\n", [keyItem objectForKey:(id)kSecAttrLabel]);
	printToStdOut(@"Application Label: %@\n", [keyItem objectForKey:(id)kSecAttrApplicationLabel]);
	//printToStdOut(@"Key Class: %@\n", keyClass);
	//printToStdOut(@"Permanent Key: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrIsPermanent]) == true ? @"True" : @"False");
	printToStdOut(@"Key Size: %@\n", [keyItem objectForKey:(id)kSecAttrKeySizeInBits]);
	printToStdOut(@"Effective Key Size: %@\n", [keyItem objectForKey:(id)kSecAttrEffectiveKeySize]);
	//printToStdOut(@"For Encryption: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanEncrypt]) == true ? @"True" : @"False");
//	printToStdOut(@"For Decryption: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanDecrypt]) == true ? @"True" : @"False");
//	printToStdOut(@"For Key Derivation: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanDerive]) == true ? @"True" : @"False");
//	printToStdOut(@"For Signatures: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanSign]) == true ? @"True" : @"False");
//	printToStdOut(@"For Signature Verification: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanVerify]) == true ? @"True" : @"False");
//	printToStdOut(@"For Key Wrapping: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanWrap]) == true ? @"True" : @"False");
//	printToStdOut(@"For Key Unwrapping: %@\n\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanUnwrap]) == true ? @"True" : @"False");

}

void printIdentity(NSDictionary *identityItem) {
	NSLog(@"==============打印Identity===================");
	SecIdentityRef identity = (SecIdentityRef)[identityItem objectForKey:(id)kSecValueRef];
	SecCertificateRef certificate;

	SecIdentityCopyCertificate(identity, &certificate);
	NSMutableDictionary *identityItemWithCertificate = [identityItem mutableCopy];
	[identityItemWithCertificate setObject:(id)certificate forKey:(id)kSecValueRef];
	printToStdOut(@"Identity\n");
	printToStdOut(@"--------\n");
	printCertificate(identityItemWithCertificate);
	printKey(identityItemWithCertificate);
	[identityItemWithCertificate release];
}

void printResultsForSecClass(NSArray *keychainItems, CFTypeRef kSecClassType) {
	NSLog(@"------printResultsForSecClass------");
	if (keychainItems == nil) {
		NSLog(@"------keychainItems为空------");
		printToStdOut(getEmptyKeychainItemString(kSecClassType));
		return;
	}
	NSLog(@"------开始遍历keychainItems------");
	NSDictionary *keychainItem;
	for (keychainItem in keychainItems) {
		if (kSecClassType == kSecClassGenericPassword) {
			printGenericPassword(keychainItem);
		}	
		else if (kSecClassType == kSecClassInternetPassword) {
			printInternetPassword(keychainItem);
		}
		else if (kSecClassType == kSecClassIdentity) {
			printIdentity(keychainItem);
		}
		else if (kSecClassType == kSecClassCertificate) {
			printCertificate(keychainItem);
		}
		else if (kSecClassType == kSecClassKey) {
			printKey(keychainItem);
		}
	}
	return;
}

#pragma mark - ********  清除帐号信息
// https://kunnan.github.io/2018/08/09/electra1131/
/*
 sqlite-wal
 sqlite-shm
 wal is a temporary write-ahead logging file
 shm is an index file for wal
 
 ➜  KCdumper git:(master) ✗ scp -r  usb2222:/private/var/mobile/Library/Accounts ~/Accounts  使用https://github.com/sqlitebrowser/sqlitebrowser/releases进行分析
 
 2018-08-12 16:55:36.372 KCdumper[9434:1481488] ==============开始获取命令行配置===================
 start kncleanAccount3Sqlite
 kncleanAccount3Sqlite sqlite3_exec:delete from ZACCOUNT where ZUSERNAME <> ""
 kncleanAccount3Sqlite :SQLITE_OK
 
 
 1、SQLite3中主要函数介绍

 sqlite3_open(文件路径,sqlite3 **)：文件名若不存在，则会自动创建
 
 sqlite3_close(sqlite3 *)：关闭数据库
 
 sqlite3__finalize(sqlite3_stmt *pStmt): 释放数据库
 
 sqlite3_errmsg(sqlite3*)：输出数据库错误
 
 sqlite3__exec(sqlite3 *,const char *sql, sqlite3_callback,void *,char **errmsg)：
 参数1：open函数得到的指针。
 参数2：一条sql语句
 
 参数3：sqlite3_callback是回调，当这条语句执行后，sqlite3会调用你提供的这个函数，回调函数
 
 参数4：void *是自己提供的指针，可以传递任何指针到这里，这个参数最终会传到回调函数里面，如果不需要传到回调函数里面，则可以设置为NULL
 
 参数5：错误信息，当执行失败时，可以查阅这个指针


 
 1、sqlite3_prepare_v2(sqlite3 *db,const char *zSql, int nByte,sqlite3_stmt **ppStmt,const char **pzTail)：
 
 参数3：表示前面sql语句的长度，如果小于0，sqlite会自动计算它的长度
 
 参数4：sqlite3_stmt指针的指针，解析后的sql语句就放在该结构里
 
 参数5：一般设为0
 
 2、sqlite3_step(sqlite3_stmt*)：
 
 参数为sqlite3_prepare_v2中的sqlite3_stmt 返回SQLITE_ROW 表示成功
 
 3、sqlite3_bind_text(sqlite3_stmt*, int, const char*, int n, void()(void)):
 
 参数1：sqlite3_prepare_v2中的sqlite3_stmt
 
 参数2：对应行数
 
 参数3：对应行数的值
 
 参数4：对应行数的值的长度，小于0自动计算长度
 
 参数5：函数指针，主要处理特殊类型的析构
 
 4、sqlite3_key( sqlite3 *db, const void *pKey, int nKey)； 可使用使用第三方的SQLite扩展库，对数据库进行整体的加密。如：SQLCipher
 
 参数2：密钥
 
 参数3：密钥长度
 https://github.com/tianjifou/CoreSQLite3
 */
static
void kncleanAccount3Sqlite() {// 获取同时删除/private/var/mobile/Library/Accounts 下的Accounts3.sqlite  sqlite-wal sqlite-shm
    sqlite3 *database;
    const char* path = "/private/var/mobile/Library/Accounts/Accounts3.sqlite";
    
    int databaseResult = sqlite3_open(path, &database);// sqlite3_open(文件路径,sqlite3 **)：文件名若不存在，则会自动创建

    if (databaseResult != SQLITE_OK) {
        NSLog(@"kn创建／打开数据库%s失败,%d",path, databaseResult);
        return;
    }
    const char *sql = "delete from ZACCOUNT where ZUSERNAME <> \"\"";
    
    char *error;
    printToStdOut(@"kncleanAccount3Sqlite sqlite3_exec:%s \n",sql);//kncleanAccount3Sqlite sqlite3_exec:delete from ZACCOUNT where ZUSERNAME <> ""

    int tableResult = sqlite3_exec(database, sql, NULL, NULL, &error);// 参数1：open函数得到的指针。参数2：一条sql语句；参数3：sqlite3_callback是回调，当这条语句执行后，sqlite3会调用你提供的这个函数，回调函数；参数4：void *是自己提供的指针，可以传递任何指针到这里，这个参数最终会传到回调函数里面，如果不需要传到回调函数里面，则可以设置为NULL；参数5：错误信息，当执行失败时，可以查阅这个指针
    



    if (tableResult != SQLITE_OK) {
        NSLog(@"kn操作失败:%@",@(error));
        printToStdOut(@"kncleanAccount3Sqlite fail:%@ \n",@(error));
    }else {
        printToStdOut(@"kncleanAccount3Sqlite :%@ \n",@"SQLITE_OK");
    }
    goto knclose;
    
knclose:
    sqlite3_close(database);// sqlite3_close(sqlite3 *)：关闭数据库

}

//-rwxr-xr-x 1 root wheel 211584 Dec  7  2017 keychain_dumper*

int main(int argc, char **argv) {
	id pool=[NSAutoreleasePool new];
	NSArray* arguments;
	arguments = getCommandLineOptions(argc, argv);
	if ([arguments indexOfObject:@"dumpEntitlements"] != NSNotFound) {
		dumpKeychainEntitlements();//  只是dumpEntitlements 而已
		exit(EXIT_SUCCESS);
    }else if ([arguments indexOfObject:@"kncleanAccount3Sqlite"] != NSNotFound){
        printToStdOut(@"start kncleanAccount3Sqlite \n");
        kncleanAccount3Sqlite();
        exit(EXIT_SUCCESS);
    }
	
	NSLog(@"==============开始获取keychain数据库===================");
	NSArray *keychainItems = nil;
	for (id kSecClassType in (NSArray *) arguments) {// 遍历要获取的信息
		keychainItems = getKeychainObjectsForSecClass((CFTypeRef)kSecClassType);
		printResultsForSecClass(keychainItems, (CFTypeRef)kSecClassType);
		[keychainItems release];
		
	}
    
	[pool drain];
}

