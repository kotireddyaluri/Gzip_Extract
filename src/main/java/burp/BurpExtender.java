package burp;

import java.awt.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private OutputStream output;


	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		// obtain an extension helpers object
		helpers = callbacks.getHelpers();

		output = callbacks.getStdout();

		// set extension name
		callbacks.setExtensionName("un/gzip body editor");

		// register ourselves as a message editor tab factory
		callbacks.registerMessageEditorTabFactory(this);

	}

	//
	// implement IMessageEditorTabFactory
	//

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		// create a new instance of custom editor tab
		return new GzipInputTab(controller, editable);
	}

	class GzipInputTab implements IMessageEditorTab {
		private boolean editable;
		private ITextEditor txtInput;
		private byte[] currentMessage;
		private byte[] unGzipContent;
		private byte[] GzipContent;

		public GzipInputTab(IMessageEditorController controller, boolean editable)
		{
			this.editable = editable;

			// create an instance of Burp's text editor, to display gzip data
			txtInput = callbacks.createTextEditor();
			txtInput.setEditable(editable);

		}

		//
		// implement IMessageEditorTab
		//

		@Override
		public String getTabCaption()
		{
			return "un/Gzip Editor";
		}

		@Override
		public Component getUiComponent()
		{
			return txtInput.getComponent();
		}

		@Override
		public boolean isEnabled(byte[] content, boolean isRequest)
		{
			// enable this tab for requests containing a data parameter

			return true;
		}

		@Override
		public void setMessage(byte[] content, boolean isRequest) throws IOException {
			// code here to un-gzip
			if (content == null)
			{
				// clear our display
				txtInput.setText(null);
				txtInput.setEditable(false);
			}
			else
			{
				IRequestInfo requestInfo = helpers.analyzeRequest(content);
				int bodyOffset = requestInfo.getBodyOffset();
				byte[] bdy = Arrays.copyOfRange(content, bodyOffset, content.length);
				try
				{
					InputStream gzipByteInputStream = new ByteArrayInputStream(bdy);

					InputStream ungzippedContent = new GZIPInputStream(gzipByteInputStream);
					Reader reader = new InputStreamReader(ungzippedContent, "UTF-8");
					Writer writer = new StringWriter();
					char[] buffer = new char[10240];
					for (int length = 0; (length = reader.read(buffer)) > 0;) {
						writer.write(buffer, 0, length);
					}
					String body = writer.toString();

					txtInput.setText(body.getBytes());
					txtInput.setEditable(editable);
				}
				catch(Exception e)
				{
					println("problem in un-gzip request- "+e.toString());
				}

			}
			// remember the displayed content
			currentMessage = content;
		}
		@Override
		public byte[] getMessage()
		{
			if(isModified())
			{
				byte[] text = txtInput.getText();
				try{
					String strMessage = new String(text);
					ByteArrayOutputStream bStream = new ByteArrayOutputStream();
					GZIPOutputStream gzip = new GZIPOutputStream(bStream);
					gzip.write(strMessage.getBytes("UTF-8"));
					gzip.close();
					byte[] gzipContent=bStream.toByteArray();

					//update request with encrypted content
					IRequestInfo requestInfo = helpers.analyzeRequest(currentMessage);
					//List<String> headers= requestInfo.getHeaders();
					currentMessage=helpers.buildHttpMessage(requestInfo.getHeaders(), gzipContent);
					//println(new String(currentMessage));
					bStream.close();

					return currentMessage;
				}
				catch (Exception e)
				{
					println(e.toString());
					return currentMessage;
				}

			}
			else return currentMessage;
		}
		@Override
		public boolean isModified()
		{
			return txtInput.isTextModified();
		}

		@Override
		public byte[] getSelectedData()
		{
			return txtInput.getSelectedText();
		}
	}
	private void println(String toPrint)
	{
		try
		{
			output.write(toPrint.getBytes());
			output.write("\n".getBytes());
			output.flush();
		}
		catch (IOException ioe)
		{
			ioe.printStackTrace();
		}
	}
}