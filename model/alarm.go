package model

type Alarm struct {
	ID       uint     `json:"alarm_id" gorm:"primary_key"`
	User     User     `json:"-"        gorm:"ForeignKey:UserID;AssociationForeignKey:Id"`
	UserID   uint     `json:"-"        gorm:"index"`
	HomeHost HomeHost `json:"-"        gorm:"ForeignKey:HostID;AssociationForeignKey:Id"`
	HostID   uint     `json:"host_id"`
	Type     int      `json:"type"`
	Desc     string   `json:"desc"`
	Img      string   `json:"img"`
	Time     JsonTime `json:"time"`
	Viewed   bool     `json:"viewed"   gorm:"default:false"`
}
