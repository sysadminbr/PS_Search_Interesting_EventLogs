<#
# CITRA IT - EXCELÊNCIA EM TI
# SCRIPT PARA EXIBIR EVENTOS NOTÁVEIS NAS ÚLTIMAS 24 HORAS.
# AUTOR: luciano@citrait.com.br
# DATA: 01/10/2021
# Homologado para executar no Windows 10 ou Server 2012R2+
# EXAMPLO DE USO: Powershell -ExecutionPolicy ByPass -File C:\scripts\Search_Observable_Security_Events.ps1
# Referências:
# https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
# https://www.ultimatewindowssecurity.com/securitylog/book/page.aspx?spid=chapter4
# https://www.ultimatewindowssecurity.com/securitylog/book/page.aspx?spid=chapter5
# $OBSERVABLE_SECURITY_EVENTS = @(1100,1101,1102,1104,1105,1108,4608,4609,4610,4611,4612,4614,4615,4616,4618,4621,4622,4624,4625,4626,4627,4634,4646,4647,4648,4649,4650,4651,4652,4653,4654,4655,4656,4657,4658,4659,4660,4661,4662,4663,4664,4665,4666,4667,4668,4670,4671,4672,4673,4674,4675,4688,4689,4690,4691,4692,4693,4694,4695,4696,4697,4698,4699,4700,4701,4702,4703,4704,4705,4706,4707,4709,4710,4711,4712,4713,4714,4715,4716,4717,4718,4719,4720,4722,4723,4724,4725,4726,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4738,4739,4740,4741,4742,4743,4744,4745,4746,4747,4748,4749,4750,4751,4752,4753,4754,4755,4756,4757,4758,4759,4760,4761,4762,4763,4764,4765,4766,4767,4768,4769,4770,4771,4772,4773,4774,4775,4776,4777,4778,4779,4780,4781,4782,4783,4784,4785,4786,4787,4788,4789,4790,4791,4792,4793,4794,4797,4798,4799,4800,4801,4802,4803,4816,4817,4818,4819,4820,4821,4822,4823,4824,4825,4826,4830,4864,4865,4866,4867,4868,4869,4870,4871,4872,4873,4874,4875,4876,4877,4878,4879,4880,4881,4882,4883,4884,4885,4886,4887,4888,4889,4890,4891,4892,4893,4894,4895,4896,4897,4898,4899,4900,4902,4904,4905,4906,4907,4908,4909,4910,4911,4912,4913,4928,4929,4930,4931,4932,4933,4934,4935,4936,4937,4944,4945,4946,4947,4948,4949,4950,4951,4952,4953,4954,4956,4957,4958,4960,4961,4962,4963,4964,4965,4976,4977,4978,4979,4980,4981,4982,4983,4984,4985,5024,5025,5027,5028,5029,5030,5031,5032,5033,5034,5035,5037,5038,5039,5040,5041,5042,5043,5044,5045,5046,5047,5048,5049,5050,5051,5056,5057,5058,5059,5060,5061,5062,5063,5064,5065,5066,5067,5068,5069,5070,5071,5120,5121,5122,5123,5124,5125,5126,5127,5136,5137,5138,5139,5140,5141,5142,5143,5144,5145,5146,5147,5148,5149,5150,5151,5152,5153,5154,5155,5156,5157,5158,5159,5168,5169,5170,5376,5377,5378,5379,5380,5381,5382,5440,5441,5442,5443,5444,5446,5447,5448,5449,5450,5451,5452,5453,5456,5457,5458,5459,5460,5461,5462,5463,5464,5465,5466,5467,5468,5471,5472,5473,5474,5477,5478,5479,5480,5483,5484,5485,5632,5633,5712,5888,5889,5890,6144,6145,6272,6273,6274,6275,6276,6277,6278,6279,6280,6281,6400,6401,6402,6403,6404,6405,6406,6407,6408,6409,6410,6416,6417,6418,6419,6420,6421,6422,6423,6424,8191)
#>

<# Events possible Fields 
ToXml
ActivityId
Bookmark
ContainerLog
Dispose
Equals
FormatDescription
GetHashCode
GetPropertyValues
GetType
Id
Keywords
KeywordsDisplayNames
Level
LevelDisplayName
LogName
MachineName
MatchedQueryIds
Message
Opcode
OpcodeDisplayName
ProcessId
Properties
ProviderId
ProviderName
Qualifiers
RecordId
RelatedActivityId
Task
TaskDisplayName
ThreadId
TimeCreated
ToString
ToXml
UserId
Version
#>

<#
Get-WinEvent -FilterHashTable could use the following fields to match events
LogName -> string
ProviderName -> string
Path -> string
Keywords -> Long
ID -> Int32
Level -> Int32
StartTime -> DateTime
EndTime -> DateTime
UserID -> SID
Data -> String  --> Matched agains all data value fields (see the event in xml to understand better)
* -> String


#>


#
# Screen Logging Function for User Feedback
#
Function Log()
{
	Param([String] $text)
	$timestamp = Get-Date -Format F
	Write-Host -ForegroundColor Green "$timestamp`: $text"
}


#
# Detecting where (path) this script is been invocated
#
$ME_PATH = Split-Path -Parent $MyInvocation.MyCommand.Path


#
# Adding windows gui forms assembly
#
Log "Loading graphical libraries"
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()



#
# Creating the main form 
#
Log "Creating main window"
$form = new-object system.windows.forms.form
$screen_width = [Int32]::Parse([System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Size.Width)
$screen_height = [Int32]::Parse([System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Size.Height)
$form.Size = New-Object System.Drawing.Size @($screen_width, $screen_height)
$form.WindowState = [System.Windows.Forms.FormWindowState]::Maximized
$form.AutoScroll = $True
$form.Text = "Eventos de Segurança Importantes (Últimas 24 horas)"
$form.Icon = New-Object System.Drawing.Icon "$ME_PATH\citra.ico"



#
# Creating the grid Control
#
$grid = new-object system.windows.forms.datagridview
$tabledata = new-object system.data.datatable
$grid.AutoSize = $true
$grid.ReadOnly = $true
$grid.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::AllCells
$grid.Dock = [System.Windows.Forms.DockStyle]::Fill



#
# Adding the grid headers
#
$tabledata.Columns.Add("Date") | out-null
$tabledata.Columns.Add("ID") | out-null
$tabledata.Columns.Add("Level") | out-null
$tabledata.Columns.Add("MachineName") | out-null
$tabledata.Columns.Add("Detalhes") | out-null




# $OBSERVABLE_SECURITY_EVENTS = @(4776,4768,4771,4769)
$OBSERVABLE_SECURITY_EVENTS = @(1100,1101,1102,1104,1105,1108,4608,4609,4610,4611,4612,4614,4615,4616,4618,4621,4622,4624,4625,4626,4627,4634,4646,4647,4648,4649,4650,4651,4652,4653,4654,4655,4656,4657,4658,4659,4660,4661,4662,4663,4664,4665,4666,4667,4668,4670,4671,4672,4673,4674,4675,4688,4689,4690,4691,4692,4693,4694,4695,4696,4697,4698,4699,4700,4701,4702,4703,4704,4705,4706,4707,4709,4710,4711,4712,4713,4714,4715,4716,4717,4718,4719,4720,4722,4723,4724,4725,4726,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4738,4739,4740,4741,4742,4743,4744,4745,4746,4747,4748,4749,4750,4751,4752,4753,4754,4755,4756,4757,4758,4759,4760,4761,4762,4763,4764,4765,4766,4767,4768,4769,4770,4771,4772,4773,4774,4775,4776,4777,4778,4779,4780,4781,4782,4783,4784,4785,4786,4787,4788,4789,4790,4791,4792,4793,4794,4797,4798,4799,4800,4801,4802,4803,4816,4817,4818,4819,4820,4821,4822,4823,4824,4825,4826,4830,4864,4865,4866,4867,4868,4869,4870,4871,4872,4873,4874,4875,4876,4877,4878,4879,4880,4881,4882,4883,4884,4885,4886,4887,4888,4889,4890,4891,4892,4893,4894,4895,4896,4897,4898,4899,4900,4902,4904,4905,4906,4907,4908,4909,4910,4911,4912,4913,4928,4929,4930,4931,4932,4933,4934,4935,4936,4937,4944,4945,4946,4947,4948,4949,4950,4951,4952,4953,4954,4956,4957,4958,4960,4961,4962,4963,4964,4965,4976,4977,4978,4979,4980,4981,4982,4983,4984,4985,5024,5025,5027,5028,5029,5030,5031,5032,5033,5034,5035,5037,5038,5039,5040,5041,5042,5043,5044,5045,5046,5047,5048,5049,5050,5051,5056,5057,5058,5059,5060,5061,5062,5063,5064,5065,5066,5067,5068,5069,5070,5071,5120,5121,5122,5123,5124,5125,5126,5127,5136,5137,5138,5139,5140,5141,5142,5143,5144,5145,5146,5147,5148,5149,5150,5151,5152,5153,5154,5155,5156,5157,5158,5159,5168,5169,5170,5376,5377,5378,5379,5380,5381,5382,5440,5441,5442,5443,5444,5446,5447,5448,5449,5450,5451,5452,5453,5456,5457,5458,5459,5460,5461,5462,5463,5464,5465,5466,5467,5468,5471,5472,5473,5474,5477,5478,5479,5480,5483,5484,5485,5632,5633,5712,5888,5889,5890,6144,6145,6272,6273,6274,6275,6276,6277,6278,6279,6280,6281,6400,6401,6402,6403,6404,6405,6406,6407,6408,6409,6410,6416,6417,6418,6419,6420,6421,6422,6423,6424,8191)


#
# Loading eventlog filtered with interesting ids
#
Log "Retrieving interesting security events"
$StartTime = (Get-Date).AddDays(-1)
$event_list = Get-WinEvent -FilterHashTable @{LogName="Security"; ProviderName="Microsoft-Windows-Security-Auditing"; StartTime=$StartTime} | Where-Object {$_.ID -in $OBSERVABLE_SECURITY_EVENTS}
Log "Found $($event_list.Count) interesting events since yesterday"


#
# Holding the queried data into a ArrayList for future consult
#
$OriginalDataSource = New-Object System.Collections.ArrayList
$event_list | %{
	$OriginalDataSource.Add(
		@(
			$_.TimeCreated, 
			$_.Id, 
			$_.LevelDisplayName, 
			$_.MachineName, 
			$_.Message
		)
	) | Out-Null
}



#
# Adding the table rows to display on grid
#
# Some events has different fields than others, so we tends to ignore fields parsing for now... ! +todo+ !
$LastErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
ForEach($obj in $OriginalDataSource)
{
	$tabledata.Rows.Add(
		@(
			$obj[0], 
			$obj[1], 
			$obj[2], 
			$obj[3], 
			$obj[4].SubString(0,200)
			#(New-Object System.Windows.Forms.Button)
		)
	) | Out-Null
}
$ErrorActionPreference = $LastErrorActionPreference


#
# Holds the current event been viewed
#
$global:CurrentViewingEvent = 0


#
# ACtion: Double click on a Row opens the event details
#
$grid.add_CellDoubleClick({
	
	#
	# Args from delegate: Object sender, Object EventArgs
	#
	$col_index = $args[1].ColumnIndex
	$row_index = $args[1].RowIndex
	$global:CurrentViewingEvent = $row_index
	
	
	# Form the event details 
	$form_detailed_info = New-Object System.Windows.Forms.Form
	$form_detailed_info.AutoScroll = $True
	$form_detailed_info.Size = New-Object System.Drawing.Size @(600,800)
	
	# Layout
	$layout = New-Object System.Windows.Forms.FlowLayoutPanel
	$layout.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
	$layout.AutoScroll = $False
	$layout.AutoSize = $True
	$layout.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowOnly
	$layout.BorderStyle = [System.Windows.Forms.BorderStyle]::None
	$layout.Dock = [System.Windows.Forms.DockStyle]::Top
	$layout.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
	$layout.Location = New-Object System.Drawing.Point @(0,0)
	$layout.Margin = New-Object System.Windows.Forms.Padding @(3,3,3,3)
	$layout.MaximumSize = New-Object System.Drawing.Size @(0,0)
	$layout.MinimumSize = New-Object System.Drawing.Size @(0,0)
	$layout.Padding = New-Object System.Windows.Forms.Padding @(0,0,0,0)
	$layout.WrapContents = $True
	
	# Previous event button
	$btnPrevious = New-Object System.Windows.Forms.Button
	$btnPrevious.Text = "Previous Event"
	$btnPrevious.AutoSize = $True
	$btnPrevious.Add_Click({
		# Checking if reached event index 0
		If($global:CurrentViewingEvent -eq 0)
		{
			[System.Windows.Forms.MessageBox]::Show("There are no previous events !")
		}else{
			$global:CurrentViewingEvent -= 1
			$label_details.Text = "`r`n`r`n" + $OriginalDataSource.Item($global:CurrentViewingEvent)[4]
			$grid.ClearSelection()
			$grid.Rows.Item($global:CurrentViewingEvent).Selected = $True
			$form_detailed_info.Refresh()
		}
		
		
	})
	
	
	# Next event button
	$btnNext = New-Object System.Windows.Forms.Button
	$btnNext.Text = "Next Event"
	$btnNext.AutoSize = $True
	$btnNext.Add_Click({
		# Checking if reached event index last
		If($global:CurrentViewingEvent -eq ($OriginalDataSource.Count-1) )
		{
			[System.Windows.Forms.MessageBox]::Show("There are no more events !")
		}else{
			$global:CurrentViewingEvent += 1
			$label_details.Text = "`r`n`r`n" + $OriginalDataSource.Item($global:CurrentViewingEvent)[4]
			$grid.ClearSelection()
			$grid.Rows.Item($global:CurrentViewingEvent).Selected = $True
			$form_detailed_info.Refresh()
		}
		
		
	})
	
	
	# RitchTextBox with event details
	$label_details = New-Object System.Windows.Forms.RichTextBox
	$label_details.AutoSize = $True
	$label_details.Multiline = $True
	$label_details.Dock = [System.Windows.Forms.DockStyle]::Fill
	$label_details.Text = "`r`n`r`n" + $OriginalDataSource.Item($row_index)[4]
	
	
	$layout.Controls.Add($btnPrevious)
	$layout.Controls.Add($btnNext)
	$form_detailed_info.Controls.Add($layout)
	$form_detailed_info.Controls.Add($label_details)
	
	#
	# Displaying the dialog with event details
	#
	$form_detailed_info.ShowDialog()
	
	
})



# Adding table data to grid
$grid.datasource = $tabledata

# Adding grid to main form window
$form.Controls.Add($grid)

#
# Making the main form visisble
#
$form.Show()
While($form.Visible)
{
	[System.Windows.Forms.Application]::DoEvents()
}




