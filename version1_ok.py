from locust import HttpUser, TaskSet, task, events
from PyAES import CAES, KeySize
import uuid
import socket
import time
import random



class WebsiteTasks(TaskSet):
    def on_start(self):
        self.UUID = (str(uuid.uuid4()).replace('-', '')).ljust(36, '\0')
        self.Network_Data = open('Network.txt', 'r').read()  # 讀取 GiveNetworkHistoryEnd
        self.Information_Data = open('Information.txt', 'r').read()  # 讀取 GiveProcessInfoEnd
        self.History_Data = open('History.txt', 'r').read()  # 讀取 Detect記憶體-GiveProcessHistoryEnd
        self.Risk_Data = open('Risk.txt', 'r').read()  # 讀取 GiveDetectProcessOver

    def AES_Payload(self, Task, check, Data=""):
        AESKey = "AES Encrypt Decrypt"
        myAES = CAES()
        myAES.SetKeys(KeySize.BIT128, AESKey)

        MAC = '\0' * 20
        IP = '\0' * 20
        DoWorking = Task.ljust(24, '\0')
        if check == '000':
            csMsg = '\0' * 924
        elif check == '0|0':
            csMsg = '0|0' + '\0' * 921
        elif check in ['Network', 'Information', 'History', 'Risk']:
            csMsg = Data.ljust(65435, '\0')
        else:
            print('Error!')
            return None

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
            network_payload_First = self.AES_Payload('GiveNetworkHistory', '000')
            time.sleep(1)
            request.send(network_payload_First)
            #print('NetworkPayloadFirst send')
            response = request.recv(1024)
            #print('GiveNetworkHistoryRespond= ',self.AES_decrypt(response))

            network_payload = self.AES_Payload('GiveNetworkHistoryEnd', 'Network', self.Network_Data)
            time.sleep(1)
            request.send(network_payload)
            #print('NetworkPayload send ')
            response = request.recv(1024)
            if response == '':
                request.close()
                return 0
            #print('GiveNetworkHistoryEndRespond= ',self.AES_decrypt(response))
            
        elif RD == 1:
            information_payload_First = self.AES_Payload('GiveProcessInformation', '000')
            time.sleep(1)
            request.send(information_payload_First)
            response = request.recv(1024)

            information_payload = self.AES_Payload('GiveProcessInfoEnd', 'Information', self.Information_Data)
            time.sleep(1)
            request.send(information_payload)
            response = request.recv(1024)
            if response == '':
                request.close()
                return 0
            
        elif RD == 2:
            history_payload_First = self.AES_Payload('GiveProcessHistory', '000')
            time.sleep(1)
            request.send(history_payload_First)
            response = request.recv(1024)

            history_payload = self.AES_Payload('GiveProcessHistoryEnd', 'History', self.History_Data)
            time.sleep(1)
            request.send(history_payload)
            response = request.recv(1024)
            if response == '':
                request.close()
                return 0
            
        elif RD == 3:
            risk_payload_First = self.AES_Payload('GiveDetectProcessRisk', '000')
            time.sleep(1)
            request.send(risk_payload_First)
            response = request.recv(1024)
            
            risk_payload = self.AES_Payload('GiveDetectProcessOver', 'Risk', self.Risk_Data)
            time.sleep(1)
            request.send(risk_payload)
            response = request.recv(1024)

            risk_payload_End = self.AES_Payload('GiveDetectProcessEnd', '000')
            time.sleep(1)
            request.send(risk_payload_End)
            response = request.recv(1024)
            if response == '':
                request.close()
                return 0
            
            

    @task
    def start_task(self):
        target_ip = '192.168.200.132'
        target_port = 1988
        target = (target_ip, target_port)
        request = socket.socket()
        request.connect(target)

        payload = self.AES_Payload('GiveInfo', '000')
        request.send(payload)
        print('GiveInfo send')
        response = request.recv(1024)
        if response == b'':
            request.close()
            return 0
        print('GiveInfoRespond = ', self.AES_decrypt(response))

        payload = self.AES_Payload('GiveDetectInfoFirst', '0|0')
        request.send(payload)
        print('GiveDetectInfoFirst send')
        response = request.recv(1024)
        print('GiveDetectInfoFirstRespond = ', self.AES_decrypt(response))

        payload = self.AES_Payload('GiveDetectInfo', '0|0')
        request.send(payload)
        print('GiveDetectInfo send')

        payload = self.AES_Payload('CheckConnect', '000')
        print('CheckConnect send')

        for i in range(100):
            RD = random.randint(0, 3)
            self.Detect(RD, request)
            time.sleep(3)


class WebsiteUser(HttpUser):
    tasks = [WebsiteTasks]
    min_wait = 1000
    max_wait = 2000


if __name__ == '__main__':
    WebsiteUser().run()