from enum import Enum, auto
from dataclasses import dataclass
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from saleae.data import GraphTime

MAP = {
        0x00: "InputPort0",
        0x01: "InputPort1",
        0x02: "OutputPort0",
        0x03: "OutputPort1",
        0x04: "PolarityInversionPort0",
        0x05: "PolarityInversionPort1",
        0x06: "ConfigurationPort0",
        0x07: "ConfigurationPort1",
        0x40: "OutputDriveStrengthRegister0",
        0x41: "OutputDriveStrengthRegister0",
        0x42: "OutputDriveStrengthRegister1",
        0x43: "OutputDriveStrengthRegister1",
        0x44: "InputLatchRegister0",
        0x45: "InputLatchRegister1",
        0x46: "PullEnableRegister0",
        0x47: "PullEnableRegister1",
        0x48: "PullSelectionRegister0",
        0x49: "PullSelectionRegister1",
        0x4A: "InterruptMaskRegister0",
        0x4B: "InterruptMaskRegister1",
        0x4C: "InterruptStatusRegister0",
        0x4D: "InterruptStatusRegister1",
        0x4F: "OutputPortConfigRegister"
}


class LLState(Enum):
    IDLE  = auto()
    START = auto()
    DATA  = auto()


@dataclass
class LLFrame:
    start_time: GraphTime
    end_time: GraphTime
    data: bytearray
    read: bool
    address: str


class IOEX6416(HighLevelAnalyzer):
    result_types = {
        "IOEX6416": {
            "format": "{{data.read}}[{{data.address}}]: {{{data.data}}}"
        },
    }

    # Settings:
    i2c_address_str  = ChoicesSetting(label='I2C Address', choices=["0x20", "0x21"])

    def __init__(self):
        self.i2c_address = int(self.i2c_address_str, 16)
        self.reset()

    def reset(self):
        self.state      = LLState.IDLE
        self.address    = None
        self.data       = bytearray()
        self.start_time = None
        self.read       = False

    def ll_fsm(self, frame):
        out = None
        if self.state == LLState.IDLE:
            if frame.type == "start":
                self.state = LLState.START
                self.start_time = frame.start_time
                return out
        elif self.state == LLState.START:
            if frame.type == "address" and frame.data["ack"]:
                self.read |= frame.data["read"]
                self.address = frame.data["address"][0]
                if self.address == self.i2c_address:
                    self.state = LLState.DATA
                    return out
        elif self.state == LLState.DATA:
            if frame.type == "data":
                self.data.extend(frame.data["data"])
                return out
            elif frame.type == "start":
                self.state = LLState.START
                return out
            elif frame.type == "stop":
                self.state = LLState.IDLE
                out = LLFrame(
                    start_time=self.start_time,
                    end_time=frame.end_time,
                    read=self.read,
                    data=self.data,
                    address=self.address
                )
        self.reset()
        return out

    def decode(self, frame: AnalyzerFrame):
        if i2c_frame := self.ll_fsm(frame):
            start_reg = i2c_frame.data[0]
            data = []
            for regaddr, regval in enumerate(i2c_frame.data[1:], start=start_reg):
                reg_name = MAP.get(regaddr, f"{regaddr:#04x}?")
                data.append(f"{reg_name}={regval:#04x}")
            return AnalyzerFrame(
                "IOEX6416",
                i2c_frame.start_time,
                i2c_frame.end_time,
                {
                    "address": hex(i2c_frame.address),
                    "read": "R" if i2c_frame.read else "W",
                    "data": "; ".join(data),
                }
            )
        return None
