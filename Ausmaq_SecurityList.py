import datetime
import io
import json
import os
import re
import urllib.parse
import smtplib
import boto3
import pandas as pd
import pytz
import turbodbc
import numpy as np
from datetime import datetime

def get_secret(secret_name, token):
    endpoint_url = "https://secretsmanager.ap-southeast-2.amazonaws.com"
    region_name = "ap-southeast-2"

    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region_name)

    get_secret_value_response = client.get_secret_value(SecretId=secret_name)

    return json.loads(get_secret_value_response['SecretString'])[token]

def send_email(host, port, username, password, subject, body, mail_to, mail_from = None, reply_to = None):
    if mail_from is None: mail_from = username
    if reply_to is None: reply_to = mail_to

    message = """From: %s\nTo: %s\nReply-To: %s\nSubject: %s\n\n%s""" % (mail_from, mail_to, reply_to, subject, body)
    #print (message)
    try:
        print('Before SMTP')
        server = smtplib.SMTP(host, port)
        print('Before ehlo')
        server.ehlo()
        print('Before TLS handshake')
        server.starttls()
        print('Before login')
        server.login(username, password)
        print('Before send email')
        server.sendmail(mail_from, mail_to, message)
        server.close()
        return True
    except Exception as ex:
        print (ex)

    return False

def lambda_handler(event, context):
    # prepare response
    response = {
        'status_code': 200,
        'message': 'SUCCESS',
        'extract_status': 'OK',
    }

    msgBody = ''

    # send mail
    success = False

    try:
        DB_Connection = os.environ['DB_CONNECTION']
        toAddress = os.environ['EMAIL_DISTRIBUTION']

        if not DB_Connection:
            print('Environment variable DB_CONNECTION not defined')
            exit(1)
        elif not toAddress:
            print('Environment variable EMAIL_DISTRIBUTION not defined')
            exit(1)

        msgBody = f"Ausmaq Security List Load - {DB_Connection} \n\n"

        # DB credentials
        DB_Server = 'ec2-13-54-149-70.ap-southeast-2.compute.amazonaws.com,5584'
        Database = f"{DB_Connection}_Powerwrap"
        UserName = 'tech_admin'
        Password = get_secret('pwl-secrets','AWS_DB_tech_admin_pw')

        # email variables
        mailUsername = "technology@powerwrap.com.au"
        mailPassword = get_secret('pwl-secrets','smtp_tech_pwd')


        # Set turbodbc AutoCommit flag to true
        connectionOptions = turbodbc.make_options(autocommit=False)

       
        

        # Get the object from the event and show its content type
        bucket_name = event['Records'][0]['s3']['bucket']['name']
        object_key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
        archive_key = object_key.replace('/','/archive/')

        msgBody = msgBody + f"File arrival detected at {(datetime.datetime.now()).strftime('%d-%m-%Y %H:%M:%S')} --> {object_key} \n"
        print("File arrived...",object_key)

        print("Connecting to S3...")
        s3 = boto3.client('s3')

        print("Getting object...")
        file_obj = s3.get_object(Bucket=bucket_name, Key=object_key)
        file_body = file_obj['Body']  # Streaming body
        

        print("Reading file...")
        csv_string = file_body.read().decode('utf-8')


        print("Parsing file...")

        df = pd.read_csv(io.StringIO(csv_string), nrows=1, header=None, encoding="ISO-8859-1" )

        df[10] = df[10].astype(str) 
        LoadedDate = df.iloc[0,10]
        
        LoadedDate = datetime.strptime(LoadedDate, '%Y%m%d').strftime('%Y-%m-%d')
        print("LoadeDate : ", LoadedDate)


        df = pd.read_csv(io.StringIO(csv_string), header=None, skiprows=1, skipfooter=1, engine='python', encoding="ISO-8859-1", index_col=False)
        # df.columns = df.columns.str.strip().str.replace(' ', '_').str.replace('(', '').str.replace(')', '')

        df = df.replace(r'^\s*$''', np.nan, regex=True)
        
        df.dropna(axis=0, how='all', inplace=True)
        df = df.fillna('')


        df[7] = df[7].astype(str).str.split('.').str[0]
        df[8] = df[8].astype(str).str.split('.').str[0]
        
        df[10] = df[10].fillna('').astype(str).str.split('.').str[0]
        df[38] = df[38].astype('str')
        df[25] = df[25].astype('str')
        df[26] = df[26].astype('str')
        df[27] = df[27].astype('str')


        if len(df) <= 0:
            raise ValueError('Zero records contained in Morningstar securityList file...ABORTING')
        #################################################################################

        print('Connecting to database...')

        conn = turbodbc.connect(DRIVER='./microsoft/msodbcsql17/lib64/libmsodbcsql-17.3.so.1.1', SERVER=DB_Server,
                                DATABASE=Database, UID=UserName,
                                PWD=Password, turbodbc_options=connectionOptions)

        msgBody = msgBody + f'Connected to database: {Database}\n'
        print(f'Connected to {Database}')
        cursor = conn.cursor()

        # Truncating Upload table
        sql = 'TRUNCATE TABLE [ausmaq].[SC_SecurityList_Upload];'

        cursor.execute(sql)
        print("Truncated")

        start = datetime.datetime.now()

        print('Inserting into Upload table:',start)

        SqlTrans = '''INSERT INTO [ausmaq].[SC_SecurityList_Upload]
                                ([RecType]
                                ,[IssuerCode]
                                ,[IssuerName]
                                ,[Description]
                                ,[LPC_SecCode]
                                ,[SecCode]
                                ,[APIR_SecCode]
                                ,[ARSN]
                                ,[ThirdPartyCode]          
                                ,[EProspectus]
                                ,[ValidDate]
                                ,[MinOrderSize]
                                ,[MarketCode]
                                ,[FundType]
                                ,[RedeemOK]
                                ,[IssueOK]
                                ,[Suspended]
                                ,[DiscDocs]
                                ,[BatchFrequency]
                                ,[BatchDay]
                                ,[BatchTime]
                                ,[Base_MER]
                                ,[ICR]
                                ,[Distribution_Freq]
                                ,[Distribution_Type]
                                ,[EffectiveDate]
                                ,[AddedDate]
                                ,[ModifiedDate]
                                ,[IssuePrice]
                                ,[RedeemPrice]
                                ,[Currency]
                                ,[UnitSize]
                                ,[Yield]
                                ,[BuyIssuePrice_LocCCY]
                                ,[SellRedeemPrice_LocCCY]
                                ,[ExchangeRate]
                                ,[GrossPrice]
                                ,[DRP_Type]
                                ,[DecPlaceHold]
                                ,[DollarRedemption]
                                ,[StateRegistered]
                                )
                                                
                                                
                                VALUES  (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) '''
        cursor.executemanycolumns(SqlTrans,[df[0].values,
                                            df[1].values,
                                            df[2].values,
                                            df[3].values,
                                            df[4].values,
                                            df[5].values,
                                            df[6].values,
                                            df[7].values ,
                                            df[8].values,
                                            df[9].values,
                                            df[10].values,
                                            df[11].values,                                                
                                            df[12].values,
                                            df[13].values,
                                            df[14].values, 
                                            df[15].values,
                                            df[16].values,
                                            df[17].values, 
                                            df[18].values, 
                                            df[19].values,
                                            df[20].values, 
                                            df[21].values,
                                            df[22].values, 
                                            df[23].values,
                                            df[24].values,
                                            df[25].values,
                                            df[26].values,
                                            df[27].values,
                                            df[28].values,
                                            df[29].values,  
                                            df[30].values,
                                            df[31].values,  
                                            df[32].values,  
                                            df[33].values,
                                            df[34].values, 
                                            df[35].values,
                                            df[36].values,
                                            df[37].values,
                                            df[38].values, 
                                            df[39].values,
                                            df[40].values  ])
        end = datetime.datetime.now()
        msgBody = msgBody + f'Number of records to be loaded : {str(cursor.rowcount)} \n'
        print("Number of records loaded : ", cursor.rowcount)
        print("Time taken:", end - start)


        sqlquery = 'SELECT MAX([Date])FROM TradingCalendar where [Date] < CAST(GETDATE() AS DATE) AND IsTradeDay = 1'
        cursor.execute(sqlquery)
        PreviousTradeDay = cursor.fetchone()
        PreviousTradeDay = PreviousTradeDay[0].strftime('%Y-%m-%d')
        print("PreviousTradeDay is",PreviousTradeDay)
        
        if LoadedDate == PreviousTradeDay :
            sql = 'EXECUTE [etl].[sp_ausmaq_SecurityList_Load] @LoadedDate=?'                
            cursor.execute(sql,[LoadedDate])
            print("*****************************************************************")
            print(f"Number of records loaded : ", cursor.rowcount)
            print("Time taken:", end-start)
            print("*****************************************************************")

        sql = 'EXECUTE [hist].[sp_ausmaq_SecurityList_Load] @LoadedDate=?'

        cursor.execute(sql,[LoadedDate])
        print("*****************************************************************")
        print(f"Number of records loaded : ", cursor.rowcount)
        print("Time taken:", end-start)
        print("*****************************************************************")
        

        
        if cursor.result_set != None:
            print("*** ERROR ***")
            error_message = []
            rows = cursor.fetchall()
            while rows:
                # print(rows)
                error_message.append(rows)
                if cursor.next:
                    rows = cursor.fetchall()
                else:
                    rows = None
            raise ValueError(error_message)

        conn.commit()
        print("Data Committed.")
        print("Data Loaded Successfully for" ,{LoadedDate})
        msgBody = msgBody +"Data Loaded Successfully"
        #########################################################################################################
        msgBody = msgBody + f'Archived {object_key} to {archive_key} \n'
        print(f'Moving {object_key} to {archive_key}...')

        # Copy file to archive
        s3.copy_object(
            ACL='public-read',
            Bucket=bucket_name,
            CopySource={'Bucket': bucket_name, 'Key': object_key},
            Key=archive_key
        )

        # remove file as its been archived
        s3.delete_object(
            Bucket=bucket_name,
            Key=object_key
        )

        print('Done')
        msgBody = msgBody + f"Completed {(datetime.datetime.now()).strftime('%d-%m-%Y %H:%M:%S')} \n"

        cursor.close()
        conn.close()

        # Construct email message
        email_sent = send_email('smtp.office365.com', 587, mailUsername, mailPassword, f'SUCCESS ({DB_Connection}) - Ausmaq Security List Load', msgBody,  toAddress, mailUsername, mailUsername)

        if not email_sent:
            success = False

    except Exception as e:
        success = False
        response['message'] = 'ERROR - \n\n' + str(e)
        msgBody = msgBody + 'ERROR - \n\n' + str(e) + '\n\n'
        email_sent = send_email('smtp.office365.com', 587, mailUsername, mailPassword, f'FAILED ({DB_Connection}) - Ausmaq Security List Load', msgBody,  toAddress, mailUsername, mailUsername)

    if success:
        response['status_code'] = 200
    else:
        response['status_code'] = 500

    return response
