from locust import HttpUser, TaskSet, task
from PyAES import CAES, KeySize
import uuid
import socket
import time
import random


class WebsiteTasks(TaskSet):
    def on_start(self):
        self.UUID = (str(uuid.uuid4()).replace('-','')).ljust(36,'\0')
        self.Network_Data = open('Network.txt', 'r').read()  # 讀取 GiveNetworkHistoryEnd
        self.Information_Data = open('Information.txt', 'r').read()  # 讀取 GiveProcessInfoEnd
        self.History_Data = open('History.txt', 'r').read()  # 讀取 Detect記憶體-GiveProcessHistoryEnd
        self.Risk_Data = open('Risk.txt', 'r').read()  # 讀取 GiveDetectProcessOver                    

                    
    def AES_Payload(self, Task, check):
        AESKey = "AES Encrypt Decrypt"
        myAES = CAES()
        myAES.SetKeys(KeySize.BIT128, AESKey)

        MAC = '\0'*20
        IP = '\0'*20
        DoWorking = Task.ljust(24, '\0')
        if check == '000':
            csMsg = '\0'*(924)
        elif check == '0|0':
            csMsg = '0|0'+'\0'*921
        elif check == 'Network':
            csMsg = self.Network_Data.ljust(65435, '\0')
        elif check == 'Information':
            csMsg = self.Information_Data.ljust(65435, '\0')
        elif check == 'History':
            csMsg = self.History_Data.ljust(65435, '\0')
        elif check == 'Risk':
            csMsg = self.Risk_Data.ljust(65435, '\0')
        else:
            print('Error!')
        payload = []
        payload += MAC + IP + self.UUID + DoWorking + csMsg
        encrypt = myAES.EncryptBuffer(payload)
        data_list = [ord(data) for data in encrypt]
        return bytearray(data_list)


    def AES_decrypt(self, Task):
        AESKey = "AES Encrypt Decrypt"
        myAES = CAES()
        myAES.SetKeys(KeySize.BIT128, AESKey)
        data_list = [chr(data) for data in Task]
        decrypt_text = myAES.DecryptBuffer(data_list)
        return ''.join(decrypt_text)


    def Detect(self, RD, request):
        if RD == 0:
                network_payload_First = self.AES_Payload('GiveNetworkHistory','000')
                time.sleep(1)
                request.send(network_payload_First)
                response = request.recv(1024)
                #print(AES_decrypt(response))

                network_payload = self.AES_Payload('GiveNetworkHistoryEnd','Network')
                time.sleep(1)
                request.send(network_payload)
                response = request.recv(1024)
                if response == '':
                        request.close()
                        return 0
        elif RD == 1:
                information_payload_First = self.AES_Payload('GiveProcessInformation','000')
                time.sleep(1)
                request.send(information_payload_First)
                response = request.recv(1024)
                #print(AES_decrypt(response))

                information_payload = self.AES_Payload('GiveProcessInfoEnd','Information')
                time.sleep(1)
                request.send(information_payload)
                response = request.recv(1024)
                #print(AES_decrypt(response))
                if response == '':
                        request.close()
                        return 0
        elif RD == 2:
                history_payload_First = self.AES_Payload('GiveProcessHistory', '000')
                time.sleep(1)
                request.send(history_payload_First)
                response = request.recv(1024)
                #print(AES_decrypt(response))

                history_payload = self.AES_Payload('GiveProcessHistoryEnd', 'History')
                time.sleep(1)
                request.send(history_payload)
                response = request.recv(1024)
                #print(AES_decrypt(response)) 
                if response == '':
                        request.close()
                        return 0
        elif RD == 3:
                risk_payload_First = self.AES_Payload('GiveDetectProcessRisk', '000')
                time.sleep(1)
                request.send(risk_payload_First)
                response = request.recv(1024)
                #print(AES_decrypt(response))

                risk_payload = self.AES_Payload('GiveDetectProcessOver', 'Risk')
                time.sleep(1)
                request.send(risk_payload)
                response = request.recv(1024)
                #print(AES_decrypt(response))

                risk_payload_End = self.AES_Payload('GiveDetectProcessEnd', '000')
                time.sleep(1)
                request.send(risk_payload_End)
                response = request.recv(1024)
                #print(AES_decrypt(response))
                if response == '':
                        request.close()
                        return 0

    def Start(self):
        target_ip = '192.168.200.132'
        target_port = 1988
        target = (target_ip,target_port)
        request = socket.socket()
        request.connect((target))

        payload = self.AES_Payload('GiveInfo','000')
        #print('Giveinfo=',payload)
        request.send(payload)
        #print('GiveInfo Send!')
        #print('GiveInfo_Response:')
        response = request.recv(1024)
        if response == '':
                return 0
        #print(AES_decrypt(response))
        payload = self.AES_Payload('GiveDetectInfoFirst','0|0')
        request.send(payload)
        #print('GiveDetectInfoFirst Send!')
        #print('GiveDetectInfoFirst_Response:')
        response = request.recv(1024)
        #print(AES_decrypt(response))
        payload = self.AES_Payload('GiveDetectInfo','0|0')
        request.send(payload)
        #print('GiveDetectInfo_Send!')
        payload = self.AES_Payload('CheckConnect','000')
        #KC = threading.Thread(target=Keep_Connect,args=(request,payload,))
        #KC.start()
        # for i in range(1000):
        #         RD = random.randint(0,3)
        #         if RD == 0:
        #                 self.Detect(0,request)
        #         elif RD == 1:
        #                 self.Detect(1,request)
        #         elif RD == 2:
        #                 self.Detect(2,request)
        #         elif RD == 3:
        #                 self.Detect(3,request)
        #         else:
        #                 print('Error!')
        #         time.sleep(3)
        #         # print(f"Survivng threads：{threading.active_count()}")



class WebsiteUser(HttpUser):
        
        tasks = [WebsiteTasks]
        min_wait = 5000
        max_wait = 15000
    
if __name__ == '__main__':
        # test = threading.Thread(target=WebsiteTasks.Start)
        # test = WebsiteTasks.Start
        # test.start()
        # time.sleep(0.2)
        WebsiteUser().run()
# ... 這裡放入 Locust 測試的相關程式碼