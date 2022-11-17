#![cfg_attr(not(feature = "std"), no_std)]

use core::result;

use embedded_hal as hal;
use hal::blocking::spi;
use hal::digital::v2::OutputPin;

use heapless::Vec;

mod picc;

/// Registers in the MFRC522, the Proximity Coupling Device (PCD) used here.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum Register {
    // Reserved         = 0x00,
    CommandReg = 0x01,
    ComlEnReg = 0x02,
    DivlEnReg = 0x03,
    ComIrqReg = 0x04,
    DivIrqReg = 0x05,
    ErrorReg = 0x06,
    Status1Reg = 0x07,
    Status2Reg = 0x08,
    FIFODataReg = 0x09,
    FIFOLevelReg = 0x0A,
    WaterLevelReg = 0x0B,
    ControlReg = 0x0C,
    BitFramingReg = 0x0D,
    CollReg = 0x0E,
    // Reserved         = 0x0F,
    // Reserved         = 0x10,
    ModeReg = 0x11,
    TxModeReg = 0x12,
    RxModeReg = 0x13,
    TxControlReg = 0x14,
    TxASKReg = 0x15,
    TxSelReg = 0x16,
    RxSelReg = 0x17,
    RxThresholdReg = 0x18,
    DemodReg = 0x19,
    // Reserved         = 0x1A,
    // Reserved         = 0x1B,
    MfTxReg = 0x1C,
    MfRxReg = 0x1D,
    // Reserved         = 0x1E,
    SerialSpeedReg = 0x1F,
    // Reserved         = 0x20,
    CRCResultRegHigh = 0x21,
    CRCResultRegLow = 0x22,
    // Reserved         = 0x23,
    ModWidthReg = 0x24,
    // Reserved         = 0x25,
    RFCfgReg = 0x26,
    GsNReg = 0x27,
    CWGsPReg = 0x28,
    ModGsPReg = 0x29,
    TModeReg = 0x2A,
    TPrescalerReg = 0x2B,
    TReloadRegHigh = 0x2C,
    TReloadRegLow = 0x2D,
    TCounterValRegHigh = 0x2E,
    TCounterValRegLow = 0x2F,
    // Reserved         = 0x30,
    TestSel1Reg = 0x31,
    TestSel2Reg = 0x32,
    TestPinEnReg = 0x33,
    TestPinValueReg = 0x34,
    TestBusReg = 0x35,
    AutoTestReg = 0x36,
    VersionReg = 0x37,
    AnalogTestReg = 0x38,
    TestDAC1Reg = 0x39,
    TestDAC2Reg = 0x3A,
    TestADCReg = 0x3B,
    // Reserved         = 0x3C-0x3F,
}
impl From<Register> for u8 {
    #[inline(always)]
    fn from(variant: Register) -> Self {
        variant as _
    }
}

const R: u8 = 1 << 7;
const W: u8 = 0 << 7;

impl Register {
    fn read_address(&self) -> u8 {
        ((*self as u8) << 1) | R
    }

    fn write_address(&self) -> u8 {
        ((*self as u8) << 1) | W
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
enum Command {
    Idle = 0b0000,
    Mem = 0b0001,
    GenerateRandomId = 0b0010,
    CalcCRC = 0b0011,
    Transmit = 0b0100,
    NoCmdChange = 0b0111,
    Receive = 0b1000,
    Transceive = 0b1100,
    MFAuthent = 0b1110,
    SoftReset = 0b1111,
}
impl From<Command> for u8 {
    #[inline(always)]
    fn from(variant: Command) -> Self {
        variant as _
    }
}

/// Errors
#[derive(Debug)]
pub enum Error<E> {
    /// Wrong Block Character Check (BCC)
    Bcc,
    /// FIFO buffer overflow
    BufferOverflow,
    /// Collision
    Collision,
    /// Wrong CRC
    Crc,
    /// Incomplete RX frame
    IncompleteFrame,
    /// Provided buffer not large enough
    NoRoom,
    /// Internal temperature sensor detects overheating
    Overheating,
    /// Parity check failed
    Parity,
    /// Error during MFAuthent operation
    Protocol,
    /// SPI bus error
    Spi(E),
    /// Timeout
    Timeout,
    /// ???
    Wr,
    /// Not acknowledge
    Nak,
    /// Proprietary frames, commands or protocols used
    Proprietary,
}

pub enum Uid {
    /// Single sized UID, 4 bytes long
    Single(GenericUid<4>),
    /// Double sized UID, 7 bytes long
    Double(GenericUid<7>),
    /// Trip sized UID, 10 bytes long
    Triple(GenericUid<10>),
}

impl Uid {
    pub fn as_bytes(&self) -> &[u8] {
        match &self {
            Uid::Single(u) => u.as_bytes(),
            Uid::Double(u) => u.as_bytes(),
            Uid::Triple(u) => u.as_bytes(),
        }
    }
}

pub struct GenericUid<const T: usize>
where
    [u8; T]: Sized,
{
    /// The UID can have 4, 7 or 10 bytes.
    bytes: [u8; T],
    /// The SAK (Select acknowledge) byte returned from the PICC after successful selection.
    sak: picc::Sak,
}

impl<const T: usize> GenericUid<T> {
    pub fn new(bytes: [u8; T], sak_byte: u8) -> Self {
        Self {
            bytes,
            sak: picc::Sak::from(sak_byte),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn is_compliant(&self) -> bool {
        self.sak.is_compliant()
    }
}

/// Answer To reQuest A
pub struct AtqA {
    bytes: [u8; 2],
}

const MIFARE_ACK: u8 = 0xA;

const MIFARE_KEYSIZE: usize = 6;
pub type MifareKey = [u8; MIFARE_KEYSIZE];

/// MFRC522 driver
pub struct Mfrc522<SPI, NSS> {
    spi: SPI,
    nss: NSS,
}

const ERR_IRQ: u8 = 1 << 1;
const IDLE_IRQ: u8 = 1 << 4;
const RX_IRQ: u8 = 1 << 5;
const TIMER_IRQ: u8 = 1 << 0;

const CRC_IRQ: u8 = 1 << 2;

impl<E, NSS, SPI> Mfrc522<SPI, NSS>
where
    SPI: spi::Transfer<u8, Error = E> + spi::Write<u8, Error = E>,
    NSS: OutputPin,
{
    /// Creates a new driver from a SPI driver and a NSS pin
    pub fn new(spi: SPI, nss: NSS) -> Result<Self, E> {
        let mut mfrc522 = Mfrc522 { spi, nss };
        mfrc522.reset()?;
        mfrc522.write(Register::TxModeReg, 0x00)?;
        mfrc522.write(Register::RxModeReg, 0x00)?;
        // Reset ModWidthReg
        mfrc522.write(Register::ModWidthReg, 0x26)?;
        // When communicating with a PICC we need a timeout if something goes wrong.
        // f_timer = 13.56 MHz / (2*TPreScaler+1) where TPreScaler = [TPrescaler_Hi:TPrescaler_Lo].
        // TPrescaler_Hi are the four low bits in TModeReg. TPrescaler_Lo is TPrescalerReg.
        mfrc522.write(Register::TModeReg, 0x80)?; // TAuto=1; timer starts automatically at the end of the transmission in all communication modes at all speeds
        mfrc522.write(Register::TPrescalerReg, 0xA9)?; // TPreScaler = TModeReg[3..0]:TPrescalerReg, ie 0x0A9 = 169 => f_timer=40kHz, ie a timer period of 25μs.
        mfrc522.write(Register::TReloadRegHigh, 0x03)?; // Reload timer with 0x3E8 = 1000, ie 25ms before timeout.
        mfrc522.write(Register::TReloadRegLow, 0xE8)?;
        mfrc522.write(Register::TxASKReg, 0x40)?; // Default 0x00. Force a 100 % ASK modulation independent of the ModGsPReg register setting
                                                  // Default 0x3F. Set the preset value for the CRC coprocessor for the CalcCRC command to 0x6363 (ISO 14443-3 part 6.2.4)
        mfrc522.write(Register::ModeReg, (0x3f & (!0b11)) | 0b01)?;
        mfrc522.rmw(Register::TxControlReg, |b| b | 0b11)?;

        Ok(mfrc522)
    }

    /// Sends a REQuest type A to nearby PICCs
    pub fn reqa<'b>(&mut self) -> Result<AtqA, Error<E>> {
        // NOTE REQA is a short frame (7 bits)
        let fifo_data = self.transceive(&[picc::Command::REQA as u8], 7, 0)?;
        if fifo_data.valid_bytes != 2 || fifo_data.valid_bits != 0 {
            Err(Error::IncompleteFrame)
        } else {
            Ok(AtqA {
                bytes: fifo_data.buffer,
            })
        }
    }

    /// Sends a Wake UP type A to nearby PICCs
    pub fn wupa<'b>(&mut self) -> Result<AtqA, Error<E>> {
        // NOTE WUPA is a short frame (7 bits)
        let fifo_data = self.transceive(&[picc::Command::WUPA as u8], 7, 0)?;
        if fifo_data.valid_bytes != 2 || fifo_data.valid_bits != 0 {
            Err(Error::IncompleteFrame)
        } else {
            Ok(AtqA {
                bytes: fifo_data.buffer,
            })
        }
    }

    /// Sends command to enter HALT state
    pub fn hlta(&mut self) -> Result<(), Error<E>> {
        let mut buffer: [u8; 4] = [picc::Command::HLTA as u8, 0, 0, 0];
        let crc = self.calculate_crc(&buffer[..2])?;
        buffer[2..].copy_from_slice(&crc);

        // The standard says:
        //   If the PICC responds with any modulation during a period of 1 ms
        //   after the end of the frame containing the HLTA command,
        //   this response shall be interpreted as 'not acknowledge'.
        // We interpret that this way: Only Error::Timeout is a success.
        match self.transceive::<0>(&buffer, 0, 0) {
            Err(Error::Timeout) => Ok(()),
            Ok(_) => Err(Error::Nak),
            Err(e) => Err(e),
        }
    }

    /// Selects a PICC in the READY state
    // TODO add optional UID to select an specific PICC
    pub fn select(&mut self, atqa: &AtqA) -> Result<Uid, Error<E>> {
        // check for proprietary anticollision
        if (atqa.bytes[0] & 0b00011111).count_ones() != 1 {
            return Err(Error::Proprietary);
        }

        // clear `ValuesAfterColl`
        self.rmw(Register::CollReg, |b| b & !0x80)
            .map_err(Error::Spi)?;

        let mut cascade_level: u8 = 0;
        let mut uid_bytes: [u8; 10] = [0u8; 10];
        let mut uid_idx: usize = 0;

        let sak = 'cascade: loop {
            let cmd = match cascade_level {
                0 => picc::Command::SelCl1,
                1 => picc::Command::SelCl2,
                2 => picc::Command::SelCl3,
                _ => unreachable!(),
            };
            let mut known_bits = 0;
            let mut tx = [0u8; 9];
            tx[0] = cmd as u8;

            // TODO: limit to 32 iterations (as spec dictates)
            'anticollision: loop {
                let tx_last_bits = known_bits % 8;
                let tx_bytes = 2 + known_bits / 8;
                let end = tx_bytes as usize + if tx_last_bits > 0 { 1 } else { 0 };
                tx[1] = (tx_bytes << 4) + tx_last_bits;

                // Tell transceive the only send `tx_last_bits` of the last byte
                // and also to put the first received bit at location `tx_last_bits`.
                // This makes it easier to append the received bits to the uid (in `tx`).
                match self.transceive::<5>(&tx[0..end], tx_last_bits, tx_last_bits) {
                    Ok(fifo_data) => {
                        fifo_data.copy_bits_to(&mut tx[2..=6], known_bits);
                        break 'anticollision;
                    }
                    Err(Error::Collision) => {
                        let coll_reg = self.read(Register::CollReg).map_err(Error::Spi)?;
                        if coll_reg & (1 << 5) != 0 {
                            // CollPosNotValid
                            return Err(Error::Collision);
                        }
                        let mut coll_pos = coll_reg & 0x1F;
                        if coll_pos == 0 {
                            coll_pos = 32;
                        }
                        if coll_pos < known_bits {
                            // No progress
                            return Err(Error::Collision);
                        }
                        let fifo_data = self.fifo_data::<5>()?;
                        fifo_data.copy_bits_to(&mut tx[2..=6], known_bits);
                        known_bits = coll_pos;

                        // Set the bit of collision position to 1
                        let count = known_bits % 8;
                        let check_bit = (known_bits - 1) % 8;
                        let index: usize =
                            1 + (known_bits / 8) as usize + if count != 0 { 1 } else { 0 };
                        tx[index] |= 1 << check_bit;
                    }
                    Err(e) => return Err(e),
                }
            }

            // send select
            tx[1] = 0x70; // NVB: 7 valid bytes
            tx[6] = tx[2] ^ tx[3] ^ tx[4] ^ tx[5]; // BCC

            let crc = self.calculate_crc(&tx[..7])?;
            tx[7..].copy_from_slice(&crc);

            let rx = self.transceive::<3>(&tx[0..9], 0, 0)?;
            if rx.valid_bytes != 3 || rx.valid_bits != 0 {
                return Err(Error::IncompleteFrame);
            }

            let sak = picc::Sak::from(rx.buffer[0]);
            let crc_a = &rx.buffer[1..];
            let crc_verify = self.calculate_crc(&rx.buffer[..1])?;
            if crc_a != &crc_verify {
                return Err(Error::Crc);
            }

            if !sak.is_complete() {
                uid_bytes[uid_idx..uid_idx + 3].copy_from_slice(&tx[3..6]);
                uid_idx += 3;
                cascade_level += 1;
            } else {
                uid_bytes[uid_idx..uid_idx + 4].copy_from_slice(&tx[2..6]);
                break 'cascade sak;
            }
        };

        match cascade_level {
            0 => Ok(Uid::Single(GenericUid {
                bytes: uid_bytes[0..4].try_into().unwrap(),
                sak,
            })),
            1 => Ok(Uid::Double(GenericUid {
                bytes: uid_bytes[0..7].try_into().unwrap(),
                sak,
            })),
            2 => Ok(Uid::Triple(GenericUid {
                bytes: uid_bytes,
                sak,
            })),
            _ => unreachable!(),
        }
    }

    /// Switch off the MIFARE Crypto1 unit.
    /// Must be done after communication with an authenticated PICC
    pub fn stop_crypto1(&mut self) -> Result<(), E> {
        self.rmw(Register::Status2Reg, |b| b & !0x08)
    }

    pub fn mf_authenticate(
        &mut self,
        uid: &Uid,
        block: u8,
        key: &MifareKey,
    ) -> Result<(), Error<E>> {
        // stop any ongoing command
        self.command(Command::Idle).map_err(Error::Spi)?;
        // clear all interrupt flags
        self.write(Register::ComIrqReg, 0x7f).map_err(Error::Spi)?;
        // flush FIFO buffer
        self.flush_fifo_buffer().map_err(Error::Spi)?;
        // clear bit framing
        self.write(Register::BitFramingReg, 0).map_err(Error::Spi)?;

        let mut tx_buffer = [0u8; 12];
        tx_buffer[0] = picc::Command::MfAuthKeyA as u8;
        tx_buffer[1] = block;
        tx_buffer[2..8].copy_from_slice(key);
        match uid {
            Uid::Single(u) => tx_buffer[8..12].copy_from_slice(&u.bytes[0..4]),
            Uid::Double(u) => tx_buffer[8..12].copy_from_slice(&u.bytes[0..4]),
            Uid::Triple(u) => tx_buffer[8..12].copy_from_slice(&u.bytes[0..4]),
        };
        // write data to transmit to the FIFO buffer
        self.write_many(Register::FIFODataReg, &tx_buffer)?;

        // signal command
        self.command(Command::MFAuthent).map_err(Error::Spi)?;

        let mut irq;
        loop {
            irq = self.read(Register::ComIrqReg).map_err(Error::Spi)?;

            if irq & (ERR_IRQ | IDLE_IRQ) != 0 {
                break;
            } else if irq & TIMER_IRQ != 0 {
                return Err(Error::Timeout);
            }
        }

        self.check_error_register()?;
        Ok(())
    }

    pub fn mf_read(&mut self, block: u8) -> Result<[u8; 16], Error<E>> {
        let mut tx = [picc::Command::MfRead as u8, block, 0u8, 0u8];

        let crc = self.calculate_crc(&tx[0..2])?;
        tx[2..].copy_from_slice(&crc);

        let rx = self.transceive::<18>(&tx, 0, 0)?.buffer;

        // verify CRC
        let crc = self.calculate_crc(&rx[..16])?;
        if &crc != &rx[16..] {
            return Err(Error::Crc);
        }
        Ok(rx[..16].try_into().unwrap())
    }

    pub fn mf_write(&mut self, block: u8, data: [u8; 16]) -> Result<(), Error<E>> {
        let mut cmd = [picc::Command::MfWrite as u8, block, 0, 0];
        let crc = self.calculate_crc(&cmd[0..2])?;
        cmd[2..].copy_from_slice(&crc);
        let fifo_data = self.transceive::<1>(&cmd, 0, 0)?;
        if fifo_data.valid_bytes != 1 || fifo_data.valid_bits != 4 {
            return Err(Error::Nak);
        }

        let mut tx = [0u8; 18];
        let crc = self.calculate_crc(&data)?;
        tx[..16].copy_from_slice(&data);
        tx[16..].copy_from_slice(&crc);
        let fifo_data = self.transceive::<1>(&tx, 0, 0)?;
        if fifo_data.valid_bytes != 1 || fifo_data.valid_bits != 4 {
            return Err(Error::Nak);
        }

        Ok(())
    }

    /// Returns the version of the MFRC522
    pub fn version(&mut self) -> Result<u8, E> {
        self.read(Register::VersionReg)
    }

    pub fn new_card_present(&mut self) -> result::Result<AtqA, Error<E>> {
        self.write(Register::TxModeReg, 0x00).map_err(Error::Spi)?;
        self.write(Register::RxModeReg, 0x00).map_err(Error::Spi)?;
        self.write(Register::ModWidthReg, 0x26)
            .map_err(Error::Spi)?;

        self.reqa()
    }

    fn calculate_crc(&mut self, data: &[u8]) -> Result<[u8; 2], Error<E>> {
        // stop any ongoing command
        self.command(Command::Idle).map_err(Error::Spi)?;

        // clear the CRC_IRQ interrupt flag
        self.write(Register::DivIrqReg, 1 << 2)
            .map_err(Error::Spi)?;

        // flush FIFO buffer
        self.flush_fifo_buffer().map_err(Error::Spi)?;

        // write data to transmit to the FIFO buffer
        self.write_many(Register::FIFODataReg, data)?;

        self.command(Command::CalcCRC).map_err(Error::Spi)?;

        // Wait for the CRC calculation to complete. Each iteration of the while-loop takes 17.73us.
        let mut irq;
        for _ in 0..5000 {
            irq = self.read(Register::DivIrqReg).map_err(Error::Spi)?;

            if irq & CRC_IRQ != 0 {
                self.command(Command::Idle).map_err(Error::Spi)?;
                let crc = [
                    self.read(Register::CRCResultRegLow).map_err(Error::Spi)?,
                    self.read(Register::CRCResultRegHigh).map_err(Error::Spi)?,
                ];

                return Ok(crc);
            }
        }
        Err(Error::Timeout)
    }

    fn check_error_register(&mut self) -> Result<(), Error<E>> {
        const PROTOCOL_ERR: u8 = 1 << 0;
        const PARITY_ERR: u8 = 1 << 1;
        const CRC_ERR: u8 = 1 << 2;
        const COLL_ERR: u8 = 1 << 3;
        const BUFFER_OVFL: u8 = 1 << 4;
        const TEMP_ERR: u8 = 1 << 6;
        const WR_ERR: u8 = 1 << 7;

        let err = self.read(Register::ErrorReg).map_err(Error::Spi)?;

        if err & PROTOCOL_ERR != 0 {
            Err(Error::Protocol)
        } else if err & PARITY_ERR != 0 {
            Err(Error::Parity)
        } else if err & CRC_ERR != 0 {
            Err(Error::Crc)
        } else if err & COLL_ERR != 0 {
            Err(Error::Collision)
        } else if err & BUFFER_OVFL != 0 {
            Err(Error::BufferOverflow)
        } else if err & TEMP_ERR != 0 {
            Err(Error::Overheating)
        } else if err & WR_ERR != 0 {
            Err(Error::Wr)
        } else {
            Ok(())
        }
    }

    // Transmit + Receive
    fn transceive<const RX: usize>(
        &mut self,
        // the data to be sent
        tx_buffer: &[u8],
        // number of bits in the last byte that will be transmitted
        tx_last_bits: u8,
        // bit position for the first received bit to be stored in the FIFO buffer
        rx_align_bits: u8,
    ) -> Result<FifoData<RX>, Error<E>>
    where
        [u8; RX]: Sized,
    {
        // stop any ongoing command
        self.command(Command::Idle).map_err(Error::Spi)?;

        // clear all interrupt flags
        self.write(Register::ComIrqReg, 0x7f).map_err(Error::Spi)?;

        // flush FIFO buffer
        self.flush_fifo_buffer().map_err(Error::Spi)?;

        // write data to transmit to the FIFO buffer
        self.write_many(Register::FIFODataReg, tx_buffer)?;

        // signal command
        self.command(Command::Transceive).map_err(Error::Spi)?;

        // configure short frame and start transmission
        self.write(
            Register::BitFramingReg,
            (1 << 7) | ((rx_align_bits & 0b0111) << 4) | (tx_last_bits & 0b0111),
        )
        .map_err(Error::Spi)?;

        // TODO timeout when connection to the MFRC522 is lost (?)
        // wait for transmission + reception to complete
        loop {
            let irq = self.read(Register::ComIrqReg).map_err(Error::Spi)?;

            if irq & (RX_IRQ | ERR_IRQ | IDLE_IRQ) != 0 {
                break;
            } else if irq & TIMER_IRQ != 0 {
                return Err(Error::Timeout);
            }
        }

        self.check_error_register()?;
        self.fifo_data()
    }

    fn fifo_data<const RX: usize>(&mut self) -> Result<FifoData<RX>, Error<E>> {
        let mut buffer = [0u8; RX];
        let mut valid_bytes = 0;
        let mut valid_bits = 0;

        if RX > 0 {
            valid_bytes = self.read(Register::FIFOLevelReg).map_err(Error::Spi)? as usize;
            if valid_bytes > RX {
                return Err(Error::NoRoom);
            }
            if valid_bytes > 0 {
                self.read_many(Register::FIFODataReg, &mut buffer[0..valid_bytes])?;
                valid_bits = (self.read(Register::ControlReg).map_err(Error::Spi)? & 0x07) as usize;
            }
        }

        Ok(FifoData {
            buffer,
            valid_bytes,
            valid_bits,
        })
    }

    fn command(&mut self, command: Command) -> Result<(), E> {
        self.write(Register::CommandReg, command.into())
    }

    fn reset(&mut self) -> Result<(), E> {
        self.command(Command::SoftReset)?;
        while self.read(Register::CommandReg)? & (1 << 4) != 0 {}
        Ok(())
    }

    fn flush_fifo_buffer(&mut self) -> Result<(), E> {
        self.write(Register::FIFOLevelReg, 1 << 7)
    }

    // lowest level  API
    fn read(&mut self, reg: Register) -> Result<u8, E> {
        let mut buffer = [reg.read_address(), 0];

        self.with_nss_low(|mfr| {
            let buffer = mfr.spi.transfer(&mut buffer)?;

            Ok(buffer[1])
        })
    }

    fn read_many<'b>(&mut self, reg: Register, buffer: &'b mut [u8]) -> Result<&'b [u8], Error<E>> {
        let mut vec = Vec::<u8, 65>::new();
        let n = buffer.len();
        for _ in 0..n {
            vec.push(reg.read_address()).map_err(|_| Error::NoRoom)?;
        }
        vec.push(0).map_err(|_| Error::NoRoom)?;

        self.with_nss_low(move |mfr| {
            let res = mfr.spi.transfer(vec.as_mut()).map_err(Error::Spi)?;

            for (idx, slot) in res[1..].iter().enumerate() {
                if idx >= n {
                    break;
                }
                buffer[idx] = *slot;
            }

            Ok(&*buffer)
        })
    }

    fn rmw<F>(&mut self, reg: Register, f: F) -> Result<(), E>
    where
        F: FnOnce(u8) -> u8,
    {
        let byte = self.read(reg)?;
        self.write(reg, f(byte))?;
        Ok(())
    }

    fn write(&mut self, reg: Register, val: u8) -> Result<(), E> {
        self.with_nss_low(|mfr| mfr.spi.write(&[reg.write_address(), val]))
    }

    fn write_many(&mut self, reg: Register, bytes: &[u8]) -> Result<(), Error<E>> {
        self.with_nss_low(|mfr| {
            let mut vec = Vec::<u8, 65>::new();
            vec.push(reg.write_address()).map_err(|_| Error::NoRoom)?;
            vec.extend_from_slice(bytes).map_err(|_| Error::NoRoom)?;
            mfr.spi.write(vec.as_slice()).map_err(Error::Spi)?;

            Ok(())
        })
    }

    fn with_nss_low<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce(&mut Self) -> T,
    {
        self.nss.set_low();
        let result = f(self);
        self.nss.set_high();

        result
    }
}

struct FifoData<const L: usize> {
    /// The contents of the FIFO buffer
    buffer: [u8; L],
    /// The number of valid bytes in the buffer
    valid_bytes: usize,
    /// The number of valid bits in the last byte
    valid_bits: usize,
}

impl<const L: usize> FifoData<L> {
    /// Copies FIFO data to destination buffer.
    /// Assumes the FIFO data is aligned properly to append directly to the current known bits.
    /// Returns the number of valid bits in the destination buffer after copy.
    pub fn copy_bits_to(&self, dst: &mut [u8], dst_valid_bits: u8) -> u8 {
        let dst_valid_bytes = dst_valid_bits / 8;
        let dst_valid_last_bits = dst_valid_bits % 8;
        let mask: u8 = (0xFF << dst_valid_last_bits) & 0xFF;
        let mut idx = dst_valid_bytes as usize;
        dst[idx] = (self.buffer[0] & mask) | (dst[idx] & !mask);
        idx += 1;
        let len = self.valid_bytes - 1;
        if len > 0 {
            dst[idx..idx + len].copy_from_slice(&self.buffer[1..=len]);
        }
        dst_valid_bits + (len * 8) as u8 + self.valid_bits as u8
    }
}
