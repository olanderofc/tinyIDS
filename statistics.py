from tabulate import tabulate

class statistics:
    def __init__(self):
        self.sport = [0] * 65536
        self.dport = [0] * 65536
        self.sessions = 0

    def updatesession(self):
        self.sessions += 1

    def updatedport(self, dport):
        self.dport[dport] += 1

    def updatesport(self, sport):
        self.sport[sport] += 1

    def showdestport(self):
        headers = ['Destination Port','Count']
        i = 1
        values = []
        for val in self.dport:
            if val > 100:
                data = [str(i - 1), str(val)]
                values.append(data)
            i += 1

        print ""
        print tabulate(values,headers,numalign='left')

    def showdsrcport(self):
        headers = ['Source Port','Count']
        i = 1
        values = []
        for val in self.sport:
            if val > 100:
                data = [str(i - 1), str(val)]
                values.append(data)
            i += 1
        print ""
        print tabulate(values,headers,numalign='left')
