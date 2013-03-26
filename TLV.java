import java.util.*;

public class TLV
{

	public static final byte ASCII = 0x01;
	public static final byte INTEGER = 0x02;
	public static final byte BINARY = 0x03;
	public static final byte STRUCTURED = 0x04;

	public static byte[] merge(byte[] a, byte[] b)
	{
		byte[] c = new byte[a.length+b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		return c;
	}

	public static Object[] decode(byte[] tlv) throws Exception
	{
		int i = 0;
		List<Object> list = new ArrayList<Object>();

		while(i < tlv.length)
		{
			switch(tlv[i])
			{
				case TLV.ASCII :
					int length1 = (256 * tlv[i+2]) + tlv[i+1];
					list.add(new String(Arrays.copyOfRange(tlv, i+3, i+3+length1), "US-ASCII"));
					i = i + 3 + length1;
					break;
				case TLV.INTEGER :
					int length2 = (256 * tlv[i+2]) + tlv[i+1];
					list.add(Integer.parseInt(new String(Arrays.copyOfRange(tlv, i+3, i+3+length2), "US-ASCII")));
					i = i + 3 + length2;
					break;
				case TLV.BINARY :
					int length3 = (256 * tlv[i+2]) + tlv[i+1];
					list.add(Arrays.copyOfRange(tlv, i+3, i+3+length3));
					i = i + 3 + length3;
					break;
				case TLV.STRUCTURED :
					int length4 = (256 * tlv[i+2]) + tlv[i+1];
					list.add(TLV.decode(Arrays.copyOfRange(tlv, i+3, i+3+length4)));
					i = i + 3 + length4;
					break;
			}
		}

		return list.toArray(new Object[list.size()]);
	}

	private byte _type, _length256, _length;
	private byte[] _data;

	public TLV(String s) throws Exception
	{
		this._type = TLV.ASCII;
		this._data = s.getBytes("US-ASCII");
		this._length256 = (byte) (this._data.length / 256);
		this._length = (byte) this._data.length;
	}

	public TLV(int i) throws Exception
	{
		this._type = TLV.INTEGER;
		String s = Integer.toString(i);
		this._data = s.getBytes("US-ASCII");
		this._length256 = (byte) (this._data.length / 256);
		this._length = (byte) this._data.length;
	}

	public TLV(byte[] b, boolean nest)
	{
		this._type = nest ? TLV.STRUCTURED : TLV.BINARY;
		this._data = b;
		this._length256 = (byte) (this._data.length / 256);
		this._length = (byte) this._data.length;
	}

	public byte getType()
	{
		return this._type;
	}

	public int getLength()
	{
		return this._length + (256 * this._length256);
	}

	public byte[] getData()
	{
		return this._data;
	}

	public byte[] getBytes()
	{
		byte[] header = {this._type, this._length, this._length256};
		return TLV.merge(header, this._data);
	}

}
