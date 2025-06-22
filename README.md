# Automation of AWS CloudTrail for multiple accounts


# How it works I have guided step by step.

Step 1 - Create trail in management account
Go to Cloudtrail console > Trails > Create trail
On the Create trail page, enter a name for your trail in Trail name.
For Storage location, choose Create new S3 bucket.
Enter a name for the bucket and prefix  in Trail log bucket and folder.
If you want to enable SSE-KMS encryption,
For Log file SSE-KMS encryption, select Enabled.
In Customer managed AWS KMS key, select New AWS KMS key. In AWS KMS Alias, enter an alias
In Additional settings [Optional]
For Log file validation,  select Enabled to deliver log digests to your S3 bucket.
For SNS notification delivery, choose Enabled to be notified each time a log is delivered to your bucket. 
Click Next.
On the Choose log events,  select Management events. [Enable data events and insights events based on your requirements]
In Management events, select the API activity you want to log.
Click Next. On the Review and create page, verify the details and click on Create Trail.





Step 2 - Update bucket policy of destination bucket
Go to Amazon S3 console > Choose the bucket you created above.
Permissions > Bucket Policy > Edit



Step 3 - Create KMS key in target accounts [Optional]
Go to Key Management Service (KMS) console > Create a key.
On Configure Key page > Select Symmetric > Click Next
On the Add labels page, Enter an AIias for the key.In Key administrators, select the IAM users and roles who can administer this key. Click Next
On the  Review page, scroll down to Key Policy. Add the permissions to your key policy


Step 4 - Create trail in target accounts 
Similar to step 1, Go to Cloudtrail console > Trails > Create trail           
On the Create trail page, enter a name for your trail in Trail name.
For Storage location, choose  Use existing S3 bucket.
Enter the name of the bucket created in Step 1.
 If you want to enable SSE-KMS encryption,
For Log file SSE-KMS encryption, select Enabled
In the Customer managed AWS KMS key, select the existing AWS KMS key. In AWS KMS Alias,  select the alias created in step 3, Click Next.
n the Choose log events,  select Management events.
In Management events, select the API activity you want to log.
Click Next. On the Review and create page, verify the details and click on Create Trail.



Step 5 - Accessing the logs in destination bucket
In the management account, go to Amazon S3 console > Select the bucket created above.
Cloudtrail will start publishing logs in the folder named after the account id of the respective account.
